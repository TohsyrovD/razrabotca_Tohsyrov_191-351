
// MFCApplication1Dlg.cpp: файл реализации
//

#include "pch.h"
#include "framework.h"
#include "MFCApplication1.h"
#include "MFCApplication1Dlg.h"
#include "afxdialogex.h"

#include "windows.h"
#include "fltuser.h"

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "fltlib.lib")
#pragma comment(lib, "fltMgr.lib")

//#ifdef _DEBUG
//#define new DEBUG_NEW
//#endif

//#ifdef _RELEASE
//#define new RELEASE_NEW
//#endif

// Диалоговое окно CAboutDlg используется для описания сведений о приложении

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Данные диалогового окна
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // поддержка DDX/DDV

// Реализация
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// Диалоговое окно CMFCApplication1Dlg



CMFCApplication1Dlg::CMFCApplication1Dlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_MFCAPPLICATION1_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMFCApplication1Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, m_EditCtrl1);
}

BEGIN_MESSAGE_MAP(CMFCApplication1Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CMFCApplication1Dlg::OnBnClickedButton1)
	ON_EN_CHANGE(IDC_EDIT1, &CMFCApplication1Dlg::OnEnChangeEdit1)
	ON_BN_CLICKED(IDC_BUTTON2, &CMFCApplication1Dlg::OnBnClickedButton2)
END_MESSAGE_MAP()


// Обработчики сообщений CMFCApplication1Dlg

BOOL CMFCApplication1Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Добавление пункта "О программе..." в системное меню.

	// IDM_ABOUTBOX должен быть в пределах системной команды.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Задает значок для этого диалогового окна.  Среда делает это автоматически,
	//  если главное окно приложения не является диалоговым
	SetIcon(m_hIcon, TRUE);			// Крупный значок
	SetIcon(m_hIcon, FALSE);		// Мелкий значок

	// TODO: добавьте дополнительную инициализацию

	return TRUE;  // возврат значения TRUE, если фокус не передан элементу управления
}

void CMFCApplication1Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// При добавлении кнопки свертывания в диалоговое окно нужно воспользоваться приведенным ниже кодом,
//  чтобы нарисовать значок.  Для приложений MFC, использующих модель документов или представлений,
//  это автоматически выполняется рабочей областью.

void CMFCApplication1Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // контекст устройства для рисования

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Выравнивание значка по центру клиентского прямоугольника
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Нарисуйте значок
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// Система вызывает эту функцию для получения отображения курсора при перемещении
//  свернутого окна.
HCURSOR CMFCApplication1Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

HANDLE port = NULL; 

void CMFCApplication1Dlg::OnBnClickedButton1()
{
	// TODO: добавьте свой код обработчика уведомлений

	DWORD byterec = 0;
	PCHAR buffer = "from usermode msg";
	char recbuffer[50] = { 0 };
	 
	if (port == NULL)
	{
		if (FilterConnectCommunicationPort(L"\\mf", 0, NULL, 0, NULL, &port)) {
			MessageBoxA(0, "test", 0, 0);
			//MessageBoxA(0, 0, 0, 0);
			return;
		}
	} 

	if (FilterSendMessage(port, buffer, strlen(buffer), recbuffer, 50, &byterec)) {

	}
	else
	{
		MessageBoxA(0, recbuffer, 0, 0);
	}
}


void CMFCApplication1Dlg::OnEnChangeEdit1()
{
	// TODO:  Если это элемент управления RICHEDIT, то элемент управления не будет
	// send this notification unless you override the CDialogEx::OnInitDialog()
	// функция и вызов CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO:  Добавьте код элемента управления
}


void CMFCApplication1Dlg::OnBnClickedButton2()
{
	// TODO: добавьте свой код обработчика уведомлений
	CString str = _T("");
	m_EditCtrl1.GetWindowTextW(str);
	
	//форматируем для вывода в отдельном всплывающем окне
	CStringA strA(str); // a helper string
	LPCSTR ptr = strA;
	MessageBoxA(0, ptr, 0, 0);

	DWORD byterec = 0;
	char recbuffer[50] = { 0 };
	char strPass[256];
	strcpy_s(strPass, CStringA(str).GetString());

	wchar_t* my_msg = (wchar_t*)ptr;

	//// TODO: добавьте свой код обработчика уведомлений
	//wchar_t* str = nullptr;
	//m_EditCtrl1.GetWindowTextW(str);

	if (port == NULL)
	{
		if (FilterConnectCommunicationPort(L"\\mf", 0, NULL, 0, NULL, &port)) {
			MessageBoxA(0, "no connection...", 0, 0);
			//MessageBoxA(0, 0, 0, 0);
			return;
		}
	}

	if (FilterSendMessage(port, my_msg, strlen(ptr), recbuffer, 50, &byterec)) {

	}
	else
	{
		MessageBoxA(0, recbuffer, 0, 0);
	}
}
