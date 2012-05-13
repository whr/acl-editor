using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Pluralsight.Security.Adapters;

namespace WpfApplication1
{
	enum TOKEN_INFORMATION_CLASS
	{
		/// <summary>
		/// The buffer receives a TOKEN_USER structure that contains the user account of the token.
		/// </summary>
		TokenUser = 1,

		/// <summary>
		/// The buffer receives a TOKEN_GROUPS structure that contains the group accounts associated with the token.
		/// </summary>
		TokenGroups,

		/// <summary>
		/// The buffer receives a TOKEN_PRIVILEGES structure that contains the privileges of the token.
		/// </summary>
		TokenPrivileges,

		/// <summary>
		/// The buffer receives a TOKEN_OWNER structure that contains the default owner security identifier (SID) for newly created objects.
		/// </summary>
		TokenOwner,

		/// <summary>
		/// The buffer receives a TOKEN_PRIMARY_GROUP structure that contains the default primary group SID for newly created objects.
		/// </summary>
		TokenPrimaryGroup,

		/// <summary>
		/// The buffer receives a TOKEN_DEFAULT_DACL structure that contains the default DACL for newly created objects.
		/// </summary>
		TokenDefaultDacl,

		/// <summary>
		/// The buffer receives a TOKEN_SOURCE structure that contains the source of the token. TOKEN_QUERY_SOURCE access is needed to retrieve this information.
		/// </summary>
		TokenSource,

		/// <summary>
		/// The buffer receives a TOKEN_TYPE value that indicates whether the token is a primary or impersonation token.
		/// </summary>
		TokenType,

		/// <summary>
		/// The buffer receives a SECURITY_IMPERSONATION_LEVEL value that indicates the impersonation level of the token. If the access token is not an impersonation token, the function fails.
		/// </summary>
		TokenImpersonationLevel,

		/// <summary>
		/// The buffer receives a TOKEN_STATISTICS structure that contains various token statistics.
		/// </summary>
		TokenStatistics,

		/// <summary>
		/// The buffer receives a TOKEN_GROUPS structure that contains the list of restricting SIDs in a restricted token.
		/// </summary>
		TokenRestrictedSids,

		/// <summary>
		/// The buffer receives a DWORD value that indicates the Terminal Services session identifier that is associated with the token.
		/// </summary>
		TokenSessionId,

		/// <summary>
		/// The buffer receives a TOKEN_GROUPS_AND_PRIVILEGES structure that contains the user SID, the group accounts, the restricted SIDs, and the authentication ID associated with the token.
		/// </summary>
		TokenGroupsAndPrivileges,

		/// <summary>
		/// Reserved.
		/// </summary>
		TokenSessionReference,

		/// <summary>
		/// The buffer receives a DWORD value that is nonzero if the token includes the SANDBOX_INERT flag.
		/// </summary>
		TokenSandBoxInert,

		/// <summary>
		/// Reserved.
		/// </summary>
		TokenAuditPolicy,

		/// <summary>
		/// The buffer receives a TOKEN_ORIGIN value.
		/// </summary>
		TokenOrigin,

		/// <summary>
		/// The buffer receives a TOKEN_ELEVATION_TYPE value that specifies the elevation level of the token.
		/// </summary>
		TokenElevationType,

		/// <summary>
		/// The buffer receives a TOKEN_LINKED_TOKEN structure that contains a handle to another token that is linked to this token.
		/// </summary>
		TokenLinkedToken,

		/// <summary>
		/// The buffer receives a TOKEN_ELEVATION structure that specifies whether the token is elevated.
		/// </summary>
		TokenElevation,

		/// <summary>
		/// The buffer receives a DWORD value that is nonzero if the token has ever been filtered.
		/// </summary>
		TokenHasRestrictions,

		/// <summary>
		/// The buffer receives a TOKEN_ACCESS_INFORMATION structure that specifies security information contained in the token.
		/// </summary>
		TokenAccessInformation,

		/// <summary>
		/// The buffer receives a DWORD value that is nonzero if virtualization is allowed for the token.
		/// </summary>
		TokenVirtualizationAllowed,

		/// <summary>
		/// The buffer receives a DWORD value that is nonzero if virtualization is enabled for the token.
		/// </summary>
		TokenVirtualizationEnabled,

		/// <summary>
		/// The buffer receives a TOKEN_MANDATORY_LABEL structure that specifies the token's integrity level.
		/// </summary>
		TokenIntegrityLevel,

		/// <summary>
		/// The buffer receives a DWORD value that is nonzero if the token has the UIAccess flag set.
		/// </summary>
		TokenUIAccess,

		/// <summary>
		/// The buffer receives a TOKEN_MANDATORY_POLICY structure that specifies the token's mandatory integrity policy.
		/// </summary>
		TokenMandatoryPolicy,

		/// <summary>
		/// The buffer receives the token's logon security identifier (SID).
		/// </summary>
		TokenLogonSid,

		/// <summary>
		/// The maximum value for this enumeration
		/// </summary>
		MaxTokenInfoClass
	}


	[System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
	public struct TOKEN_DEFAULT_DACL
	{

		/// PACL->ACL*
		public System.IntPtr DefaultDacl;
	}


	[System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
	public struct TOKEN_OWNER
	{

		/// PSID->PVOID->void*
		public System.IntPtr Owner;
	}


	[System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
	public struct TOKEN_PRIMARY_GROUP
	{

		/// PSID->PVOID->void*
		public System.IntPtr PrimaryGroup;
	}

	[System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
	public struct ACL
	{

		/// BYTE->unsigned char
		public byte AclRevision;

		/// BYTE->unsigned char
		public byte Sbz1;

		/// WORD->unsigned short
		public ushort AclSize;

		/// WORD->unsigned short
		public ushort AceCount;

		/// WORD->unsigned short
		public ushort Sbz2;
	}

	/// <summary>
	/// Interaction logic for MainWindow.xaml
	/// </summary>
	public partial class MainWindow : Window
	{
		[DllImport("advapi32.dll", SetLastError = true)]
		static extern bool GetTokenInformation(
			IntPtr TokenHandle,
			TOKEN_INFORMATION_CLASS TokenInformationClass,
			IntPtr TokenInformation,
			uint TokenInformationLength,
			out int ReturnLength);

		public MainWindow()
		{
			InitializeComponent();
		}

		private void Button_Click(object sender, RoutedEventArgs e)
		{
			WindowsIdentity user = WindowsIdentity.GetCurrent();
			if (user != null)
			{
				int length = 0;
				IntPtr token = user.Token;
				GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenDefaultDacl, IntPtr.Zero, 0, out length);
				IntPtr TokenInformation = Marshal.AllocHGlobal((int)length);
				bool Result = GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenDefaultDacl, TokenInformation, (uint)length, out length);
				TOKEN_DEFAULT_DACL dacl = (TOKEN_DEFAULT_DACL)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_DEFAULT_DACL));
				ACL acl = (ACL)Marshal.PtrToStructure(dacl.DefaultDacl, typeof(ACL));

				byte[] aceArr = new byte[acl.AclSize];
				Marshal.Copy(dacl.DefaultDacl, aceArr, 0, acl.AclSize);

				RawAcl rawAcl = new RawAcl(aceArr, 0);

				DiscretionaryAcl dacl1 = new DiscretionaryAcl(false, false, rawAcl);


				string titel = "titel";

				AclUIAdapter.EditSecurity(new ServiceSecurityModel(System.Environment.MachineName, titel));
			}
		}

		class ServiceSecurityModel : ISecurityInformationManaged
		{
			string machineName;
			string serviceName;
			public ServiceSecurityModel(string machineName, string serviceName)
			{
				this.machineName = machineName;
				this.serviceName = serviceName;
			}

			public ObjectInfo GetObjectInformation()
			{
				return new ObjectInfo(
					ObjectInfoFlags.EditAll | ObjectInfoFlags.PageTitle | ObjectInfoFlags.Advanced | ObjectInfoFlags.Reset,
					machineName,
					serviceName,
					"Service Security");
			}


			public AccessRights GetAccessRights(ValueType objectType,
				ObjectInfoFlags flags)
			{
				AccessRights rights = new AccessRights();
				Access[] access = rights.Access = new Access[17];

				// these aliases should make the code more readable
				// for the magazine edition (we don't get much width!)
				AccessFlags G = AccessFlags.General;
				AccessFlags S = AccessFlags.Specific;

				// summary page permissions
				access[0] = new Access(SERVICE_ALL, "Full Control", G | S);
				access[1] = new Access(SERVICE_READ, "Read", G);
				access[2] = new Access(SERVICE_WRITE, "Write", G);
				access[3] = new Access(SERVICE_EXECUTE, "Execute", G);

				// advanced page permissions
				access[4] = new Access(0x0001, "Query Configuration", S);
				access[5] = new Access(0x0002, "Change Configuration", S);
				access[6] = new Access(0x0004, "Query Status", S);
				access[7] = new Access(0x0008, "Enumerate Dependents", S);
				access[8] = new Access(0x0010, "Start", S);
				access[9] = new Access(0x0020, "Stop", S);
				access[10] = new Access(0x0040, "Pause or Continue", S);
				access[11] = new Access(0x0080, "Interrogate", S);
				access[12] = new Access(0x0100, "Send User Defined Control", S);
				access[13] = new Access(0x00010000, "Delete", S);
				access[14] = new Access(0x00020000, "Read Permissions", S);
				access[15] = new Access(0x00040000, "Change Permissions", S);
				access[16] = new Access(0x00080000, "Take Ownership", S);

				// note how I refer to access[1] as the default ("Read")
				rights.DefaultIndex = 1;

				return rights;
			}

			public InheritType[] GetInheritTypes()
			{
				return null; // services are not containers
			}

			// these generic mappings taken from the service access rights documentation
			const int SERVICE_READ = 0x0002008D;
			const int SERVICE_WRITE = 0x00020002;
			const int SERVICE_EXECUTE = 0x00020170;
			const int SERVICE_ALL = 0x000F01FF;

			const int GENERIC_READ = unchecked((int)0x80000000);
			const int GENERIC_WRITE = 0x40000000;
			const int GENERIC_EXECUTE = 0x20000000;
			const int GENERIC_ALL = 0x10000000;

			GenericMapping ServiceGenericMapping = new GenericMapping(
			  SERVICE_READ, SERVICE_WRITE, SERVICE_EXECUTE, SERVICE_ALL);

			public void MapGeneric(GenericAccess generic)
			{
				MapGenericMask(ref generic.Mask, ref ServiceGenericMapping);
			}
			public void SetSecurity(SecurityInformation providedInformation, byte[] binarySecurityDescriptor)
			{
			}
			public byte[] GetSecurity(SecurityInformation requestedInformation, bool wantDefault)
			{
				//FileSecurity fsec= new FileSecurity(@"c:\Test1\test.txt",~AccessControlSections.Audit);
				//return fsec.GetSecurityDescriptorBinaryForm();
				WindowsIdentity user = WindowsIdentity.GetCurrent();
				if (user != null)
				{
					int length = 0;
					IntPtr token = user.Token;
					GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenDefaultDacl, IntPtr.Zero, 0, out length);
					IntPtr TokenInformation = Marshal.AllocHGlobal((int) length);
					bool Result = GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenDefaultDacl, TokenInformation, (uint) length,
					                                  out length);
					TOKEN_DEFAULT_DACL dacl =
						(TOKEN_DEFAULT_DACL) Marshal.PtrToStructure(TokenInformation, typeof (TOKEN_DEFAULT_DACL));
					ACL acl = (ACL) Marshal.PtrToStructure(dacl.DefaultDacl, typeof (ACL));

					byte[] aceArr = new byte[acl.AclSize];
					Marshal.Copy(dacl.DefaultDacl, aceArr, 0, acl.AclSize);

					RawAcl rawAcl = new RawAcl(aceArr, 0);


					Marshal.FreeHGlobal(TokenInformation);
					GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenOwner, IntPtr.Zero, 0, out length);
					TokenInformation = Marshal.AllocHGlobal((int) length);
					GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenOwner, TokenInformation, (uint)length,
													  out length);
					TOKEN_OWNER tokOwner = (TOKEN_OWNER) Marshal.PtrToStructure(TokenInformation, typeof (TOKEN_OWNER));
					SecurityIdentifier ownerSID= new SecurityIdentifier(tokOwner.Owner);


					Marshal.FreeHGlobal(TokenInformation);
					GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenPrimaryGroup, IntPtr.Zero, 0, out length);
					TokenInformation = Marshal.AllocHGlobal((int)length);
					GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenPrimaryGroup, TokenInformation, (uint)length,
													  out length);
					TOKEN_PRIMARY_GROUP tokGroup= (TOKEN_PRIMARY_GROUP)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_PRIMARY_GROUP));
					SecurityIdentifier groupSID = new SecurityIdentifier(tokGroup.PrimaryGroup);

					RawSecurityDescriptor rawDesc = new RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent, ownerSID, groupSID, null, rawAcl);
					byte[] ret = new byte[rawDesc.BinaryLength];
					rawDesc.GetBinaryForm(ret, 0);
					return ret;

				}
				return null;
			}

			[DllImport("advapi32.dll")]
			static extern void MapGenericMask(ref int mask, ref GenericMapping mapping);
		}

	}
}