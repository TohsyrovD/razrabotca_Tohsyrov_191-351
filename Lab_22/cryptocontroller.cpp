#include "cryptocontroller.h"
#include <QString>
#include <openssl/evp.h>
#include <QFile>
#include <QIODevice>
#include <QObject>
#include <openssl/conf.h>
#include <QQmlContext>
#include <QDebug>
#include <QClipboard>
#include <QGuiApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QJsonArray>
#include <QByteArray>
#include <QProcess>
#include <QClipboard>
#include <atlstr.h>
#include <Windows.h>
#include <intrin.h>
#include <iostream>
#include <string.h>

using namespace std;

cryptoController::cryptoController(QObject *parent) : QObject(parent)
{

}

void cryptoController::text_to_clipboard(QString text, QString pin) {
    text = decrypt_login_or_password(text, pin);
    QClipboard *clipboard = QGuiApplication::clipboard();
    QString originalText = clipboard->text();
    clipboard->setText(text);
}

QString cryptoController::decrypt_login_or_password(QString text, QString password) {
    EVP_CIPHER_CTX *ctx;
    if(!(ctx = EVP_CIPHER_CTX_new())){ //EVP_CIPHER_CTX_new() creates a cipher context.
        emit sendMessageToQml("РџСЂРѕРёР·РѕС€Р»Р° РѕС€РёР±РєР°.");
        return "";
    }

    QString key = password + ((QString)"0").repeated(32 - password.length());

    iv = (unsigned char*) key.data();

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, (unsigned char*) key.data(), iv))
    {
        return "";
    }

    unsigned char ciphertext[256] = {0};
    unsigned char plaintext[256] = {0};
    int len = 0, plaintext_len = 256;
    QString db_decrypted = "";

    QByteArray line = QByteArray::fromBase64(text.toUtf8());
    int s = line.size();
    if (s<256)
        plaintext_len=s;
    memcpy(plaintext, line.toStdString().c_str(), plaintext_len);


    //QFile file("C:\\Lab_2\\Lab_2\\out.txt");
    //file.open(QIODevice::WriteOnly);
    QByteArray ciphertext_qbyte;
    while(s > 0){
        if(1 != EVP_DecryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        {
            emit sendMessageToQml("РџСЂРѕРёР·РѕС€Р»Р° РѕС€РёР±РєР°.");
            return "";
        }

        ciphertext_qbyte = QByteArray(((char *) ciphertext), len);
        //file.write(ciphertext_qbyte);

        line.remove(0, 256);
        s-=256;
        if (s<0)
            break;
        if (s<256)
            plaintext_len=s;
        memcpy(plaintext, line.toStdString().c_str(), plaintext_len);

    }

    //file.close();



    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_qbyte;
}

bool cryptoController::check_password(QString password) {
    EVP_CIPHER_CTX *ctx;
    if(!(ctx = EVP_CIPHER_CTX_new())){ //EVP_CIPHER_CTX_new() creates a cipher context.
        return 0;
    }

    QString key = password + ((QString)"0").repeated(32 - password.length());

    iv = (unsigned char*) key.data();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, (unsigned char*) key.data(), iv))
    {
        return false;
    }

    unsigned char ciphertext[256] = {0};
    unsigned char plaintext[256] = {0};
    int len = 0, plaintext_len = password.length();

    memcpy(plaintext, password.toStdString().c_str(), password.size());

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        return false;
    }

    QString password_cipher = (char *)ciphertext;
    QByteArray password_cipher_qbyte = (char*) ciphertext;

    char buffer[256] = {0};
    QFile source_file(":/password_crypt.txt");
    bool is_opened = source_file.open(QIODevice::ReadOnly);
    source_file.read(buffer, 256);


    source_file.close();
    EVP_CIPHER_CTX_free(ctx);

    return QString(buffer) == password_cipher_qbyte.toBase64();
}

void cryptoController::decrypt_db_file(QString password, int record_id, int is_password)
{
    EVP_CIPHER_CTX *ctx;
        if(!(ctx = EVP_CIPHER_CTX_new())){ //EVP_CIPHER_CTX_new() creates a cipher context.
            emit sendMessageToQml("РџСЂРѕРёР·РѕС€Р»Р° РѕС€РёР±РєР°.");
            return;
        }

        QString key = password + ((QString)"0").repeated(32 - password.length());

        iv = (unsigned char*) key.data();

        if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, (unsigned char*) key.data(), iv))
        //EVP_EncryptInit_ex() sets up cipher context "ctx" for encryption with cipher "EVP_aes_256_cfb()"
        //from ENGINE "NULL" (If impl is NULL then the default implementation is used.)
        {
            return;
        }

        unsigned char ciphertext[256] = {0};
        unsigned char plaintext[256] = {0};
        int len = 0, plaintext_len = 0;
        QString db_decrypted = "";

        QFile source_file(":/db_crypt.json");
        bool is_opened = source_file.open(QIODevice::ReadOnly);
        if(!is_opened) {
            emit sendMessageToQml("РћС€РёР±РєР° РїСЂРё РѕС‚РєСЂС‹С‚РёРё С„Р°Р№Р»Р° СЃ СѓС‡РµС‚РЅС‹РјРё РґР°РЅРЅС‹РјРё.");
            return;
        }

        plaintext_len = source_file.read((char *)plaintext, 256);

        while(plaintext_len > 0){
            if(1 != EVP_DecryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
            {
                emit sendMessageToQml("РџСЂРѕРёР·РѕС€Р»Р° РѕС€РёР±РєР°.");
                return;
            }

            QByteArray ciphertext_qbyte = QByteArray(((char *) ciphertext), len);
            db_decrypted += ciphertext_qbyte;

            plaintext_len = source_file.read((char *)plaintext, 256);
        }

        EVP_CIPHER_CTX_free(ctx);

        if(record_id != -1 && is_password != -1)
            get_login_and_password(db_decrypted, record_id, is_password, key);
        else
            emit sendDbToQml(db_decrypted);
}

void cryptoController::encrypt_db_file(QString password, int record_id, int is_password)
{

    EVP_CIPHER_CTX *ctx;
        if(!(ctx = EVP_CIPHER_CTX_new())){ //EVP_CIPHER_CTX_new() creates a cipher context.
            emit sendMessageToQml("РџСЂРѕРёР·РѕС€Р»Р° РѕС€РёР±РєР°.");
            return;
        }

        QString key = password + ((QString)"0").repeated(32 - password.length());

        iv = (unsigned char*) key.data();

        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, (unsigned char*) key.data(), iv))
        //EVP_EncryptInit_ex() sets up cipher context "ctx" for encryption with cipher "EVP_aes_256_cfb()"
        //from ENGINE "NULL" (If impl is NULL then the default implementation is used.)
        {
            return;
        }

        unsigned char ciphertext[256] = {0};
        unsigned char plaintext[256] = {0};
        int len = 0, plaintext_len = 0;
        QString db_decrypted = "";

        QFile source_file(":/db.json");
        bool is_opened = source_file.open(QIODevice::ReadOnly);
        if(!is_opened) {
            emit sendMessageToQml("РћС€РёР±РєР° РїСЂРё РѕС‚РєСЂС‹С‚РёРё С„Р°Р№Р»Р° СЃ СѓС‡РµС‚РЅС‹РјРё РґР°РЅРЅС‹РјРё.");
            return;
        }

        plaintext_len = source_file.read((char *)plaintext, 256);


        QFile file("C:\\Lab_22\\db_crypt.json");
        file.open(QIODevice::WriteOnly);

        while(plaintext_len > 0){
            if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
            {
                emit sendMessageToQml("РџСЂРѕРёР·РѕС€Р»Р° РѕС€РёР±РєР°.");
                return;
            }

            QByteArray ciphertext_qbyte = QByteArray(((char *) ciphertext), len);
            db_decrypted += ciphertext_qbyte;

            file.write((char *)ciphertext, len);
            plaintext_len = source_file.read((char *)plaintext, 256);
        }


        EVP_CIPHER_CTX_free(ctx);

        if(record_id != -1 && is_password != -1)
            get_login_and_password(db_decrypted, record_id, is_password, key);
        else
            emit sendDbToQml(db_decrypted);
}

void cryptoController::get_login_and_password(QString db_decrypted, int record_id, int is_password, QString key)
{
    QJsonDocument jsonResponse = QJsonDocument::fromJson(db_decrypted.toUtf8());
    QJsonObject jsonObject = jsonResponse.object();

//    qDebug() << jsonObject.value("sites").type();

    if((jsonObject.value("sites")).type() == QJsonValue::Array) {
        QJsonArray qjsonarray = jsonObject.value("sites").toArray();
        QJsonValue val = is_password ? qjsonarray.at(record_id).toObject().value("password") : qjsonarray.at(record_id).toObject().value("login");

//        decryptData(val.toString());
//        qDebug() << (qjsonarray.at(record_id)).type();
//        qDebug() << val.toString();

//        QString daaa = val.toString().toUtf8();
        QByteArray cipher_data = QByteArray::fromBase64(val.toString().toUtf8());

        EVP_CIPHER_CTX *ctx;
        if(!(ctx = EVP_CIPHER_CTX_new())){ //EVP_CIPHER_CTX_new() creates a cipher context.
            emit sendMessageToQml("РџСЂРѕРёР·РѕС€Р»Р° РѕС€РёР±РєР°.");
            return;
        }

        iv = (unsigned char*) key.data();
        if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, (unsigned char*) key.data(), iv))
        {
            emit sendMessageToQml("РџСЂРѕРёР·РѕС€Р»Р° РѕС€РёР±РєР°.");
            return;
        }

        unsigned char ciphertext[256] = {0};
        unsigned char plaintext[256] = {0};
        int len = 0;
        memcpy(plaintext, cipher_data.toStdString().c_str(), cipher_data.size());

        if(1 != EVP_DecryptUpdate(ctx, ciphertext, &len, plaintext, cipher_data.size()))
        {
            emit sendMessageToQml("РџСЂРѕРёР·РѕС€Р»Р° РѕС€РёР±РєР°.");
            return;
        }

        QByteArray ciphertext_qbyte = QByteArray(((char *) ciphertext), len);

//        qDebug() << ciphertext_qbyte;

        QClipboard* clp = QGuiApplication::clipboard();
        clp->setText(ciphertext_qbyte);
        emit sendMessageToQml("РЎРєРѕРїРёСЂРѕРІР°РЅРѕ РІ Р±СѓС„РµСЂ РѕР±РјРµРЅР°.");

    } else return;
}

//        QFile file("C:\\Lab_22\\db_crypt.json");
//        file.open(QIODevice::WriteOnly);

//        //зашифрование данных
//        while(plaintext_len > 0){
//            if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
//            {
//                return;
//            }

//            QByteArray ciphertext_qbyte = QByteArray(((char *) ciphertext), len);

//            file.write((char *)ciphertext, len);
//            plaintext_len = source_file.read((char *)plaintext, 256);
//        }


//        EVP_CIPHER_CTX_free(ctx);
//}
