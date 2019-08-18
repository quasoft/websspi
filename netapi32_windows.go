package websspi

//go:generate go run $GOROOT/src/syscall/mksyscall_windows.go -output znetapi32_windows.go netapi32_windows.go

const (
	NERR_Success       = 0x0
	NERR_InternalError = 0x85C
	NERR_UserNotFound  = 0x8AD

	ERROR_ACCESS_DENIED     = 0x5
	ERROR_BAD_NETPATH       = 0x35
	ERROR_INVALID_LEVEL     = 0x7C
	ERROR_INVALID_NAME      = 0x7B
	ERROR_MORE_DATA         = 0xEA
	ERROR_NOT_ENOUGH_MEMORY = 0x8

	MAX_PREFERRED_LENGTH = 0xFFFFFFFF

	SE_GROUP_MANDATORY          = 0x1
	SE_GROUP_ENABLED_BY_DEFAULT = 0x2
	SE_GROUP_ENABLED            = 0x4
	SE_GROUP_OWNER              = 0x8
	SE_GROUP_USE_FOR_DENY_ONLY  = 0x10
	SE_GROUP_INTEGRITY          = 0x20
	SE_GROUP_INTEGRITY_ENABLED  = 0x40
	SE_GROUP_LOGON_ID           = 0xC0000000
	SE_GROUP_RESOURCE           = 0x20000000
)

type GroupUsersInfo0 struct {
	Grui0_name *uint16
}

type GroupUsersInfo1 struct {
	Grui1_name       *uint16
	Grui1_attributes uint32
}

//sys	NetUserGetGroups(serverName *uint16, userName *uint16, level uint32, buf **byte, prefmaxlen uint32, entriesread *uint32, totalentries *uint32) (neterr error) = netapi32.NetUserGetGroups
