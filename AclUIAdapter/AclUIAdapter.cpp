// This is the main DLL file.

#include "stdafx.h"
#include <vcclr.h>
//#include <_vcclrit.h>

#include <memory>
#include <vector>
#include <iostream>

#include <sddl.h>

using namespace System;
using namespace System::Runtime::InteropServices;
using std::exception;
#pragma comment(lib, "aclui.lib")

const wchar_t* const COMPONENT_NAME = L"Managed AclUI Adapter";

static wstring _toWstring(String^ managedString) {
    pin_ptr<const wchar_t> pinnedInternalString = PtrToStringChars(managedString);
    return wstring(pinnedInternalString);
}

static wchar_t* _toZString(String^ managedString) {
    const int cch = managedString->Length;
    std::auto_ptr<wchar_t> s(new wchar_t[cch+1]);
    pin_ptr<const wchar_t> pinnedInternalString = PtrToStringChars(managedString);
    CopyMemory(s.get(), pinnedInternalString, sizeof(wchar_t)*(cch+1));
    return s.release();
}

static HRESULT _convertToCOMException(HRESULT hr, wstring description) {
    ICreateErrorInfo* pcei;
    HRESULT hrInternal = CreateErrorInfo(&pcei);
    if (FAILED(hrInternal)) return hrInternal;

    pcei->SetSource(const_cast<wchar_t*>(COMPONENT_NAME));
    pcei->SetDescription(const_cast<wchar_t*>(description.c_str()));

    IErrorInfo* pei;
    hrInternal = pcei->QueryInterface(&pei);
    pcei->Release(); pcei = 0;
    if (FAILED(hrInternal)) return hrInternal;

    hrInternal = SetErrorInfo(0, pei);
    pei->Release();
    if (FAILED(hrInternal)) return hrInternal;

    return hr; 
}

class NativeException {
    wstring m_msg;
    HRESULT m_hr;
public:
    NativeException(wstring msg) : m_msg(msg), m_hr(E_FAIL) {}
    NativeException(HRESULT hr, wstring msg) : m_msg(msg), m_hr(hr) {}
    
    HRESULT ConvertToCOMException() const {
       return _convertToCOMException(m_hr, m_msg);
    }
};

static void _throwWin32Exception(const wchar_t* fcn, DWORD err = GetLastError()) {
    wchar_t m[128];
    if (!FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, err, 0, m, sizeof m / sizeof *m, 0)) {
        wsprintf(m, L"0x%08X", err);
    }
    throw new NativeException(HRESULT_FROM_WIN32(err), wstring(fcn).append(L" failed: ").append(m));
}

static wstring _toUnicode(string s) {
    size_t cch = mbstowcs(0, s.c_str(), s.length());
    std::auto_ptr<wchar_t> p(new wchar_t[cch+1]);
    if (cch != mbstowcs(p.get(), s.c_str(), s.length()))
        throw NativeException(E_FAIL, L"mbstowcs failed");
    p.get()[cch] = L'\0';
    return wstring(p.get());
}

static HRESULT _convertToCOMException(const exception& x) {
    return _convertToCOMException(E_FAIL, _toUnicode(x.what()));
}

static System::Guid^ _toManagedGuid(const GUID& rawGuid) {
	array<Byte,1>^ data = gcnew array<Byte,1>(sizeof rawGuid);
    //Byte data[] = new Byte[sizeof rawGuid];
    pin_ptr<Byte>  pinnedData = &data[0];
    CopyMemory(pinnedData, &rawGuid, sizeof rawGuid);
    return gcnew System::Guid(data);
}

static array<Byte,1>^ _toManagedArray(void* p, int cb) {
    array<Byte,1>^ a = gcnew array<Byte,1>(cb);
    pin_ptr<Byte>  pinned = &a[0];
    CopyMemory(pinned, p, cb);
    return a;
}

static BOOL _isSameLuid(const LUID& a, const LUID& b) {
    return a.LowPart == b.LowPart && a.HighPart == b.HighPart;
}

static BOOL _userHasPrivilege(const wchar_t* priv) {
    HANDLE htok;
    TOKEN_PRIVILEGES* tp = 0;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &htok)) {
        DWORD err = GetLastError();
        if (ERROR_NO_TOKEN == err) {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &htok)) {
                _throwWin32Exception(L"OpenProcessToken");
            }
        }
        else _throwWin32Exception(L"OpenThreadToken", err);
    }
    try {
        LUID luid;
        if (!LookupPrivilegeValue(0, priv, &luid)) {
            _throwWin32Exception(L"LookupPrivilegeValue");
        }
        DWORD cb;
        GetTokenInformation(htok, TokenPrivileges, 0, 0, &cb);
        tp = (TOKEN_PRIVILEGES*)LocalAlloc(LMEM_FIXED, cb);
        if (!tp) {
            _throwWin32Exception(L"LocalAlloc");
        }
        if (!GetTokenInformation(htok, TokenPrivileges, tp, cb, &cb)) {
            _throwWin32Exception(L"GetTokenInformation");
        }
        for (DWORD i = 0; i < tp->PrivilegeCount; ++i) {
            if (_isSameLuid(luid, tp->Privileges[i].Luid)) return TRUE;
        }
    }
    __finally {
        if (tp) LocalFree(tp);
        CloseHandle(htok);
    }
    return FALSE;
}

namespace Pluralsight {
namespace Security {
namespace Adapters {

[Flags]
public  enum class ObjectInfoFlags : unsigned int {
    EditPerms               = 0x00000000,
    EditOwner               = 0x00000001,
    EditAudit               = 0x00000002,
    EditAll                 = 0x00000003, // EditPerms | EditOwner | EditAudit
    Container               = 0x00000004,
    ReadOnly                = 0x00000008,
    Advanced                = 0x00000010,
    Reset                   = 0x00000020,
    OwnerReadOnly           = 0x00000040,
    EditProperties          = 0x00000080,
    OwnerRecurse            = 0x00000100,
    NoAclProtect            = 0x00000200,
    NoTreeApply             = 0x00000400,
    PageTitle               = 0x00000800,
    ServerIsDC              = 0x00001000,
    ResetDaclTree           = 0x00004000,
    ResetSaclTree           = 0x00008000,
    ObjectGuid              = 0x00010000,
    EditEffective           = 0x00020000,
    ResetDacl               = 0x00040000,
    ResetSacl               = 0x00080000,
    ResetOwner              = 0x00100000,
    NoAdditionalPermission  = 0x00200000,
    MayWrite                = 0x10000000,
};
public ref struct ObjectInfo {
    ObjectInfoFlags Flags;
    String^ ServerName;
    String^ ObjectName;
    String^ PageTitle;  // ignored unless ObjectInfoFlags.PageTitle is set
    Guid    ObjectType; // ignored unless ObjectInfoFlags.ObjectGuid is set

    ObjectInfo(ObjectInfoFlags flags, String^ serverName, String^ objectName, String^ pageTitle, Guid objectType)
    {
        Flags = flags;
        ServerName = serverName;
        ObjectName = objectName;
        PageTitle = pageTitle;
        ObjectType = objectType;
        if (PageTitle) Flags = (ObjectInfoFlags)(Flags | ObjectInfoFlags::PageTitle);
    }
    ObjectInfo(ObjectInfoFlags flags, String^ serverName, String^ objectName, String^ pageTitle)
    {
        Flags = flags;
        ServerName = serverName;
        ObjectName = objectName;
        PageTitle = pageTitle;
        if (PageTitle) Flags = (ObjectInfoFlags)(Flags | ObjectInfoFlags::PageTitle);
    }
};

[Flags]
public enum class AccessFlags : unsigned int {
    Specific  = 0x00010000,
    General   = 0x00020000,
    Container = 0x00040000, // general access, container-only
    Property  = 0x00080000,
};


public ref struct Access {
    System::Guid^        Guid; // leave this empty unless you are using Active Directory style ACLs
    int         Mask;
    String^     Name;
    AccessFlags Flags;

    Access(System::Guid^ guid, int mask, String^ name, AccessFlags flags)
        : Guid(guid), Mask(mask), Name(name), Flags(flags)
    {}
    Access(int mask, String^ name, AccessFlags flags)
        : Mask(mask), Name(name), Flags(flags)
    {}
};

[Flags]
public enum class InheritFlags : unsigned char {
    Object = 1,
    Container = 2,
    InheritOnly = 8
};

public value struct InheritType {
    Guid^         guid;
    InheritFlags flags;
    String^      name;

    InheritType(InheritFlags flags, String^ name) {
        this->flags = flags;
        this->name = name;
    }
    InheritType(Guid^ guid, InheritFlags flags, String^ name) {
        this->guid = guid;
        this->flags = flags;
        this->name = name;
    }
};

[Flags]
public enum class SecurityInformation : unsigned int {
    Owner           = 0x00000001,
    Group           = 0x00000002,
    Dacl            = 0x00000004,
    Sacl            = 0x00000008,
    ProtectedDacl   = 0x80000000,
    ProtectedSacl   = 0x40000000,
    UnprotectedDacl = 0x20000000,
    UnprotectedSacl = 0x10000000,
};

[Flags]
public enum class AceFlags : unsigned char {
    ObjectInherit = 1,
    ContainerInherit = 2,
    NoPropagateInherit = 4,
    InheritOnly = 8,
    Inherited = 0x10,
    SuccessAudit = 0x40,
    FailureAudit = 0x80
};

public ref struct AccessRights {
    array<Access^,1>^ Access;
    int DefaultIndex; // indicates the item in Access array that
                        // should be used for default rights for new objects
};

public ref struct GenericAccess {
    Guid^     ObjectType;
    AceFlags AceFlags;
    int      Mask;
};

public  interface class ISecurityInformationManaged {
  ObjectInfo^ GetObjectInformation();
  AccessRights^ GetAccessRights(Guid^ objectType, ObjectInfoFlags flags);
  array<Byte,1>^ GetSecurity(SecurityInformation requestedInformation, bool wantDefault);
  void SetSecurity(SecurityInformation providedInformation, array<Byte,1>^ binarySecurityDescriptor);
  void MapGeneric(GenericAccess^ gen);
  array<InheritType,1>^ GetInheritTypes();
};

// here's our custom COM Callable Wrapper (CCW)
struct SecurityInfoCCW : public ISecurityInformation {
    typedef std::vector<GUID*> GuidVector;
    long m_cRefs;
    gcroot<ISecurityInformationManaged^> m_model;
    wstring m_serverName;
    wstring m_objectName;
    wstring m_pageTitle;
    std::auto_ptr<SI_ACCESS> m_access;
    std::auto_ptr<SI_INHERIT_TYPE> m_inheritTypes;
    std::vector<wchar_t*> m_strings;
    GuidVector m_guids;
    static const GUID _emptyGuid;

    SecurityInfoCCW(ISecurityInformationManaged^ model)
      : m_cRefs(0), m_model(model)
    {}

    ~SecurityInfoCCW() {
        for (GuidVector::iterator it = m_guids.begin(); it != m_guids.end(); ++it) {
            delete *it;
        }
    }

    const wchar_t* _pushString(String^ managedString) {
        std::auto_ptr<wchar_t> s(_toZString(managedString));
        m_strings.push_back(s.get());
        return s.release();
    }

    const GUID* _pushGuid(System::Guid^ managedGuid) {
        if (System::Guid::Empty == managedGuid) {
            return &_emptyGuid;
        }
        //pin_ptr<System::Guid>  pinned = managedGuid;
		Guid^ pinned = managedGuid;
		
		
  //      std::auto_ptr<GUID> nativeGuid(new GUID(*reinterpret_cast<GUID*>(pinned)));
		//nativeGuid->Data1=pinned->Data1;
  //      m_guids.push_back(nativeGuid.get());
        return 0;//nativeGuid.release();
    }

    DWORD _preprocessFlags(ObjectInfoFlags flags) {
        DWORD processedFlags = (DWORD)flags;
        if ((processedFlags & SI_EDIT_AUDITS) && !_userHasPrivilege(SE_SECURITY_NAME)) {
            // turn off auditing tab if user isn't privileged enough to view/edit audits
            processedFlags &= ~SI_EDIT_AUDITS;
        }
        return processedFlags;
    }

    STDMETHODIMP GetObjectInformation( SI_OBJECT_INFO* poi ) {
        OutputDebugString(L"GetObjectInformation");
        try {
            ObjectInfo^ oi = m_model->GetObjectInformation();
            if (!oi) {
                throw NativeException(L"Managed implementation returned null for GetObjectInformation");
            }
            if (oi->ServerName) {
                m_serverName = _toWstring(oi->ServerName);
            }
            if (oi->ObjectName) {
                m_objectName = _toWstring(oi->ObjectName);
            }
            if (oi->PageTitle) {
                m_pageTitle = _toWstring(oi->PageTitle);
            }
            poi->dwFlags = _preprocessFlags(oi->Flags);

            poi->hInstance = GetModuleHandle(0); // we don't use this feature anyway
            if (m_serverName.length() > 0) {
                poi->pszServerName = const_cast<wchar_t*>(m_serverName.c_str());
            }
            poi->pszObjectName  = const_cast<wchar_t*>(m_objectName.c_str());
            if (m_pageTitle.length() > 0) {
                poi->dwFlags |= SI_PAGE_TITLE;
                poi->pszPageTitle = const_cast<wchar_t*>(m_pageTitle.c_str());
            }
            return S_OK;
        }
        catch (const NativeException& x) {
            return x.ConvertToCOMException();
        }
        catch (const exception& x) {
            return _convertToCOMException(x);
        }
    }

    STDMETHODIMP GetAccessRights(const GUID* objectTypeGuid,
                                 DWORD dwFlags,
                                 SI_ACCESS** ppAccess,
                                 ULONG* pcAccesses,
                                 ULONG* piDefaultAccess ) {
        OutputDebugString(L"GetAccessRights");
        try {
            Guid^ objectType = Guid::Empty;
            if (objectTypeGuid) {
                objectType = _toManagedGuid(*objectTypeGuid);
            }
            AccessRights^ rights = m_model->GetAccessRights(objectType, (ObjectInfoFlags)dwFlags);
            array<Access^,1>^ accessDescriptors = rights->Access;
            const int c = accessDescriptors->Length;
            m_access.reset(new SI_ACCESS[c]);
            for (int i = 0; i < c; ++i) {
                SI_ACCESS& raw = m_access.get()[i];
                Access^ managed = accessDescriptors[i];
                if (!managed->Name) throw gcnew ApplicationException(String::Format("ISecurityInformationManaged.GetAccessRights returned a null Name in element {0} of the Access array", i));
                raw.dwFlags = (DWORD) managed->Flags;
                raw.mask = managed->Mask;
                raw.pszName = _pushString(managed->Name);
                raw.pguid = _pushGuid(managed->Guid);
            }
            // set up the default access mask
            *ppAccess = m_access.get();
            *pcAccesses = c;
            *piDefaultAccess = rights->DefaultIndex;
            return S_OK;
        }
        catch (const exception& x) {
            return _convertToCOMException(x);
        }
    }

    STDMETHODIMP GetSecurity(SECURITY_INFORMATION requestedInformation, void** ppsd, BOOL wantDefault) {
        OutputDebugString(L"GetSecurity");
        if (!ppsd) return E_POINTER;
        try {
            array<Byte,1>^ sd = m_model->GetSecurity((SecurityInformation)requestedInformation, wantDefault ? true : false);
            if (!sd) throw gcnew ApplicationException("ISecurityInformationManaged::GetSecurity returned a null value");
            std::auto_ptr<char> psd(new char[sd->Length]);
            pin_ptr<Byte> pinnedSD = &sd[0];
            CopyMemory(psd.get(), pinnedSD, sd->Length);
            *ppsd = psd.release();
            return S_OK;
        }
        catch (const exception& x) {
            return _convertToCOMException(x);
        }
    }

    STDMETHODIMP SetSecurity(SECURITY_INFORMATION providedInformation, void* psdFromUI) {
        OutputDebugString(L"SetSecurity");
        if (!psdFromUI) return E_POINTER;
        try {
            m_model->SetSecurity((SecurityInformation)providedInformation,
                _toManagedArray(psdFromUI, GetSecurityDescriptorLength(psdFromUI)));
            return S_OK;
        }
        catch (const exception& x) {
            return _convertToCOMException(x);
        }
    }

    STDMETHODIMP MapGeneric(const GUID* objectType, UCHAR* pAceFlags, ACCESS_MASK* pMask) {
        OutputDebugString(L"MapGeneric");
        if (!pAceFlags || !pMask) return E_POINTER;
        try {
            GenericAccess^ ga = gcnew GenericAccess();
            ga->AceFlags = (AceFlags)*pAceFlags;
            ga->Mask = *pMask;
            if (objectType) ga->ObjectType = _toManagedGuid(*objectType);
            m_model->MapGeneric(ga);
            *pAceFlags = (UCHAR)ga->AceFlags;
            *pMask = ga->Mask;
            return S_OK;
        }
        catch (const exception& x) {
            return _convertToCOMException(x);
        }
    }

    STDMETHODIMP GetInheritTypes( SI_INHERIT_TYPE** ppInheritTypes, ULONG* pcInheritTypes ) {
        OutputDebugString(L"GetInheritTypes");
        if (!ppInheritTypes || !pcInheritTypes) return E_POINTER;
        try {
            array<InheritType,1>^ results = m_model->GetInheritTypes();
            if (!results) {
                *ppInheritTypes = 0;
                *pcInheritTypes = 0;
                return S_OK;
            }
            const int count = results->Length;
            m_inheritTypes.reset(new SI_INHERIT_TYPE[count]);
            for (int i = 0; i < count; ++i) {
                InheritType^ src = results[i];
                SI_INHERIT_TYPE& dst = m_inheritTypes.get()[i];
                dst.dwFlags = (ULONG)src->flags;
                dst.pguid   = _pushGuid(src->guid);
                dst.pszName = _pushString(src->name);
            }
            *ppInheritTypes = m_inheritTypes.get();
            *pcInheritTypes = count;
            return S_OK;
        }
        catch (const exception& x) {
            return _convertToCOMException(x);
        }
    }

    STDMETHODIMP PropertySheetPageCallback( HWND hwnd, UINT msg, SI_PAGE_TYPE pt ) {
        // we don't implement this
        return S_OK;
    }
    // boy this really takes ya back down memory lane, doesn't it? ;-)
    STDMETHODIMP QueryInterface(REFIID iid, void** ppv) {
        if (IID_IUnknown == iid || IID_ISecurityInformation == iid)
             *ppv = static_cast<ISecurityInformation*>(this);
        else return (*ppv = 0), E_NOINTERFACE;
        reinterpret_cast<IUnknown*>(*ppv)->AddRef();
        return S_OK;
    }

    STDMETHODIMP_(ULONG) AddRef() {
        return ++m_cRefs;
    }

    STDMETHODIMP_(ULONG) Release() {
        ULONG n = --m_cRefs;
        if ( 0 == n )
            delete this;
        return n;
    }
};

const GUID SecurityInfoCCW::_emptyGuid = GUID_NULL;

public enum class ObjectType : int {
    UnknownObjectType = 0,
    FileObject, 
    Service, 
    Printer, 
    RegistryKey, 
    Lmshare, 
    KernelObject, 
    WindowObject, 
    DsObject, 
    DsObjectAll, 
    ProviderDefinedObject, 
    WmiguidObject, 
    RegistryWow6432key,
};

[StructLayout(LayoutKind::Sequential)]
public value struct GenericMapping {
    int GenericRead;
    int GenericWrite;
    int GenericExecute;
    int GenericAll;

    GenericMapping(int read, int write, int execute, int all) {
        GenericRead = read;
        GenericWrite = write;
        GenericExecute = execute;
        GenericAll = all;
    }
};

public ref struct AclUIAdapter {
    static bool EditSecurity(ISecurityInformationManaged^ model) {
        return EditSecurity(model, HWND_DESKTOP);
    }
    static bool EditSecurity(ISecurityInformationManaged^ model, HWND hwndOwner) {
        ISecurityInformation* psi = new SecurityInfoCCW(model);
        psi->AddRef();
        BOOL result = ::EditSecurity(hwndOwner, psi);
        psi->Release();
        return result ? true : false;
    }

    //static array<Byte,1>^ GetNamedSecurityInformation(String^ name, ObjectType objectType, SecurityInformation requestedInformation) {
    //    void* psd;
    //    wchar_t __pin* pinnedName = PtrToStringChars(name);
    //    DWORD result = ::GetNamedSecurityInfo(pinnedName, (SE_OBJECT_TYPE)objectType, requestedInformation, 0, 0, 0,0, &psd);
    //    if (result) {
    //        throw new ApplicationException("GetNamedSecurityInfo failed");
    //    }
    //    try {
    //        return _toManagedArray(psd, GetSecurityDescriptorLength(psd));
    //    }
    //    __finally {
    //        LocalFree(psd);
    //    }
    };
};



}
}