package main

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type MetricasSistema struct {
	CPUPercent    float64
	MemTotal      uint64
	MemUsada      uint64
	MemLivre      uint64
	MemPercent    float64
	Uptime        string
	Discos        []MetricaDisco
	PortasAbertas []PortaAberta
}

type MetricaDisco struct {
	Letra     string
	Total     uint64
	Livre     uint64
	Usado     uint64
	Percentual float64
}

type PortaAberta struct {
	Porta     string
	Protocolo string
	Estado    string
	Processo  string
}

var (
	modkernel32       = windows.NewLazySystemDLL("kernel32.dll")
	procGetTickCount64 = modkernel32.NewProc("GetTickCount64")
	modpsapi          = windows.NewLazySystemDLL("psapi.dll")
)

func obterUptime() string {
	ret, _, _ := procGetTickCount64.Call()
	ms := uint64(ret)
	segundos := ms / 1000
	dias := segundos / 86400
	horas := (segundos % 86400) / 3600
	minutos := (segundos % 3600) / 60

	if dias > 0 {
		return fmt.Sprintf("%dd %dh %dm", dias, horas, minutos)
	}
	return fmt.Sprintf("%dh %dm", horas, minutos)
}

func obterMemoria() (total, usada, livre uint64, percent float64) {
	type memoryStatusEx struct {
		dwLength                uint32
		dwMemoryLoad            uint32
		ullTotalPhys            uint64
		ullAvailPhys            uint64
		ullTotalPageFile        uint64
		ullAvailPageFile        uint64
		ullTotalVirtual         uint64
		ullAvailVirtual         uint64
		ullAvailExtendedVirtual uint64
	}

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	globalMemoryStatusEx := kernel32.NewProc("GlobalMemoryStatusEx")

	var ms memoryStatusEx
	ms.dwLength = uint32(unsafe.Sizeof(ms))
	globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms)))

	total = ms.ullTotalPhys
	livre = ms.ullAvailPhys
	usada = total - livre
	percent = float64(usada) / float64(total) * 100
	return
}

func obterDiscos() []MetricaDisco {
	var discos []MetricaDisco
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getDiskFreeSpaceEx := kernel32.NewProc("GetDiskFreeSpaceExW")

	letras := []string{"C:", "D:", "E:", "F:"}
	for _, letra := range letras {
		path, _ := windows.UTF16PtrFromString(letra + "\\")
		var livre, total, totalLivre uint64
		ret, _, _ := getDiskFreeSpaceEx.Call(
			uintptr(unsafe.Pointer(path)),
			uintptr(unsafe.Pointer(&livre)),
			uintptr(unsafe.Pointer(&total)),
			uintptr(unsafe.Pointer(&totalLivre)),
		)
		if ret == 0 || total == 0 {
			continue
		}
		usado := total - livre
		percent := float64(usado) / float64(total) * 100
		discos = append(discos, MetricaDisco{
			Letra:      letra,
			Total:      total,
			Livre:      livre,
			Usado:      usado,
			Percentual: percent,
		})
	}
	return discos
}

func obterPortas() []PortaAberta {
	out, err := exec.Command("netstat", "-ano").Output()
	if err != nil {
		return nil
	}

	// Portas relevantes pra monitorar
	portasRelevantes := map[string]bool{
		"3389": true, "8585": true, "80": true,
		"443": true, "445": true, "135": true,
		"22": true, "21": true, "25": true,
	}

	var portas []PortaAberta
	vistas := map[string]bool{}

	linhas := strings.Split(string(out), "\n")
	for _, linha := range linhas {
		campos := strings.Fields(linha)
		if len(campos) < 4 {
			continue
		}
		proto := campos[0]
		if proto != "TCP" && proto != "UDP" {
			continue
		}

		endereco := campos[1]
		partes := strings.Split(endereco, ":")
		if len(partes) < 2 {
			continue
		}
		porta := partes[len(partes)-1]

		if !portasRelevantes[porta] {
			continue
		}

		estado := ""
		if proto == "TCP" && len(campos) >= 4 {
			estado = campos[3]
		}

		if estado != "LISTENING" && estado != "ESTABLISHED" {
			continue
		}

		chave := proto + porta + estado
		if vistas[chave] {
			continue
		}
		vistas[chave] = true

		portas = append(portas, PortaAberta{
			Porta:     porta,
			Protocolo: proto,
			Estado:    estado,
		})
	}
	return portas
}

func obterCPU() float64 {
	type fileTime struct {
		dwLowDateTime  uint32
		dwHighDateTime uint32
	}
	toUint64 := func(ft fileTime) uint64 {
		return uint64(ft.dwHighDateTime)<<32 | uint64(ft.dwLowDateTime)
	}

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getSystemTimes := kernel32.NewProc("GetSystemTimes")

	var idle1, kernel1, user1 fileTime
	getSystemTimes.Call(
		uintptr(unsafe.Pointer(&idle1)),
		uintptr(unsafe.Pointer(&kernel1)),
		uintptr(unsafe.Pointer(&user1)),
	)

	// Aguarda 500ms pra calcular diferença
	time.Sleep(500 * time.Millisecond)

	var idle2, kernel2, user2 fileTime
	getSystemTimes.Call(
		uintptr(unsafe.Pointer(&idle2)),
		uintptr(unsafe.Pointer(&kernel2)),
		uintptr(unsafe.Pointer(&user2)),
	)

	idleDiff := toUint64(idle2) - toUint64(idle1)
	kernelDiff := toUint64(kernel2) - toUint64(kernel1)
	userDiff := toUint64(user2) - toUint64(user1)
	total := kernelDiff + userDiff
	if total == 0 {
		return 0
	}
	return float64(total-idleDiff) / float64(total) * 100
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func obterMetricas() MetricasSistema {
	memTotal, memUsada, memLivre, memPercent := obterMemoria()
	return MetricasSistema{
		CPUPercent: obterCPU(),
		MemTotal:   memTotal,
		MemUsada:   memUsada,
		MemLivre:   memLivre,
		MemPercent: memPercent,
		Uptime:     obterUptime(),
		Discos:     obterDiscos(),
		PortasAbertas: obterPortas(),
	}
}

var (
	modwtsapi32sess       = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSDisconnect     = modwtsapi32sess.NewProc("WTSDisconnectSession")
	procWTSSendMessage    = modwtsapi32sess.NewProc("WTSSendMessageW")
	procWTSEnumSess2      = modwtsapi32sess.NewProc("WTSEnumerateSessionsW")
	procWTSQuerySessInfo2 = modwtsapi32sess.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory3    = modwtsapi32sess.NewProc("WTSFreeMemory")
)

func obterSessionID(usuario string) uint32 {
	var pSessoes uintptr
	var count uint32

	ret, _, _ := procWTSEnumSess2.Call(0, 0, 1,
		uintptr(unsafe.Pointer(&pSessoes)),
		uintptr(unsafe.Pointer(&count)),
	)
	if ret == 0 {
		return 0
	}
	defer procWTSFreeMemory3.Call(pSessoes)

	type wtsSessionInfo struct {
		SessionID      uint32
		WinStationName *uint16
		State          uint32
	}

	size := unsafe.Sizeof(wtsSessionInfo{})
	for i := uint32(0); i < count; i++ {
		s := (*wtsSessionInfo)(unsafe.Pointer(pSessoes + uintptr(i)*size))
		if s.State != 0 {
			continue
		}
		var pNome uintptr
		var nomeSize uint32
		ret, _, _ := procWTSQuerySessInfo2.Call(
			0,
			uintptr(s.SessionID),
			5,
			uintptr(unsafe.Pointer(&pNome)),
			uintptr(unsafe.Pointer(&nomeSize)),
		)
		if ret == 0 || pNome == 0 {
			continue
		}
		nome := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(pNome)))
		procWTSFreeMemory3.Call(pNome)
		if strings.EqualFold(nome, usuario) {
			return s.SessionID
		}
	}
	return 0
}

func desconectarUsuario(usuario string) bool {
	sessionID := obterSessionID(usuario)
	if sessionID == 0 {
		return false
	}
	ret, _, _ := procWTSDisconnect.Call(0, uintptr(sessionID), 0)
	return ret != 0
}

func enviarMensagem(usuario string, titulo string, mensagem string) bool {
	sessionID := obterSessionID(usuario)
	if sessionID == 0 {
		return false
	}

	tituloPtr, _ := windows.UTF16PtrFromString(titulo)
	msgPtr, _ := windows.UTF16PtrFromString(mensagem)
	var response uint32

	ret, _, _ := procWTSSendMessage.Call(
		0,
		uintptr(sessionID),
		uintptr(unsafe.Pointer(tituloPtr)),
		uintptr(len(titulo)*2),
		uintptr(unsafe.Pointer(msgPtr)),
		uintptr(len(mensagem)*2),
		0x00000000, // MB_OK
		30,
		uintptr(unsafe.Pointer(&response)),
		0,
	)
	return ret != 0
}