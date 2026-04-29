package main

import (
	"database/sql"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	_ "modernc.org/sqlite"
)

var db *sql.DB

func iniciarDB() {
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	dbPath := filepath.Join(exeDir, "rdp-monitor.db")

	var err error
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatal("Erro ao abrir banco:", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS acessos (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp  DATETIME NOT NULL,
			evento_id  INTEGER,
			tipo       TEXT,
			usuario    TEXT,
			ip_origem  TEXT,
			computador TEXT,
			logon_type TEXT,
			ativa      INTEGER DEFAULT 0
		)
	`)
	if err != nil {
		log.Fatal("Erro ao criar tabela:", err)
	}
	
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS ips_bloqueados (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			ip         TEXT NOT NULL UNIQUE,
			motivo     TEXT,
			tentativas INTEGER DEFAULT 0,
			bloqueado_em DATETIME NOT NULL
		)
	`)
	if err != nil {
		log.Fatal("Erro ao criar tabela ips_bloqueados:", err)
	}	

	// Ao iniciar, zera todas as sessões ativas — estado desconhecido
	db.Exec(`UPDATE acessos SET ativa = 0 WHERE ativa = 1`)
	log.Println("Banco de dados pronto:", dbPath)
}

/*
*/
func salvarEvento(ev *RDPEvent) {
	if ev.Usuario == "" || ev.Usuario == "-" {
		return
	}

	if ev.EventID != 21 && ev.EventID != 25 {
		if ev.LogonType == "5" || ev.LogonType == "0" || ev.LogonType == "2" {
			return
		}
	}

	prefixosIgnorar := []string{"DWM-", "UMFD-", "ANONYMOUS", "SISTEMA", "SYSTEM"}
	for _, p := range prefixosIgnorar {
		if strings.EqualFold(ev.Usuario, p) || strings.HasPrefix(strings.ToUpper(ev.Usuario), strings.ToUpper(p)) {
			return
		}
	}

	// Ignora EventID 21 com LOCAL — é boot do sistema, não RDP
	if ev.EventID == 21 && (ev.IPOrigem == "LOCAL" || ev.IPOrigem == "" || ev.IPOrigem == "-") {
		return
	}

	// Ignora EventID 23 (logoff TerminalServices) — já tratado pelo encerrarSessao
	if ev.EventID == 23 {
		return
	}

	// Ignora 4624 LogonType=10 quando já existe RECONECT (EventID 25) no mesmo segundo
	if ev.EventID == 4624 && ev.LogonType == "10" {
		var count int
		db.QueryRow(`SELECT COUNT(*) FROM acessos WHERE usuario = ? AND evento_id = 25 AND timestamp = ?`,
			ev.Usuario, ev.Timestamp.Format(time.RFC3339)).Scan(&count)
		if count > 0 {
			return
		}
	}

	ativa := 0
	if ev.EventID == 4624 && ev.LogonType == "10" {
		ativa = 1
		db.Exec(`UPDATE acessos SET ativa = 0 WHERE usuario = ? AND ativa = 1`, ev.Usuario)
	}
	if ev.EventID == 21 && ev.IPOrigem != "" && ev.IPOrigem != "-" && ev.IPOrigem != "LOCAL" {
		ativa = 1
		db.Exec(`UPDATE acessos SET ativa = 0 WHERE usuario = ? AND ativa = 1`, ev.Usuario)
	}
	if ev.EventID == 25 {
		ativa = 1
		db.Exec(`UPDATE acessos SET ativa = 0 WHERE usuario = ? AND ativa = 1`, ev.Usuario)
	}

	log.Printf("SALVAR: EventID=%d Usuario=%s LogonType=%s IP=%s Ativa=%d\n",
		ev.EventID, ev.Usuario, ev.LogonType, ev.IPOrigem, ativa)

	_, err := db.Exec(`
		INSERT INTO acessos (timestamp, evento_id, tipo, usuario, ip_origem, computador, logon_type, ativa)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.Timestamp.Format(time.RFC3339),
		ev.EventID,
		ev.Tipo,
		ev.Usuario,
		ev.IPOrigem,
		ev.Computador,
		ev.LogonType,
		ativa,
	)
	if err != nil {
		log.Println("Erro ao salvar evento:", err)
	}
}

func buscarAcessos(limite int) []RDPEvent {
	rows, err := db.Query(`
		SELECT timestamp, evento_id, tipo, usuario, ip_origem, computador, logon_type
		FROM acessos
		ORDER BY timestamp DESC
		LIMIT ?`, limite)
	if err != nil {
		log.Println("Erro ao buscar acessos:", err)
		return nil
	}
	defer rows.Close()

	var eventos []RDPEvent
	for rows.Next() {
		var ev RDPEvent
		var tsStr string
		rows.Scan(&tsStr, &ev.EventID, &ev.Tipo, &ev.Usuario, &ev.IPOrigem, &ev.Computador, &ev.LogonType)
		ev.Timestamp, _ = time.Parse(time.RFC3339, tsStr)
		eventos = append(eventos, ev)
	}
	return eventos
}

func encerrarSessao(usuario string, timestamp time.Time) {
	log.Printf("ENCERRAR SESSAO: Usuario=%s Timestamp=%s\n", usuario, timestamp.Format("15:04:05"))
	db.Exec(`
		UPDATE acessos SET ativa = 0
		WHERE usuario = ? AND ativa = 1 AND timestamp < ?`,
		usuario,
		timestamp.Format(time.RFC3339),
	)
}

func buscarSessoesAtivas() []RDPEvent {
	rows, err := db.Query(`
		SELECT timestamp, evento_id, tipo, usuario, ip_origem, computador, logon_type
		FROM acessos
		WHERE ativa = 1
		ORDER BY timestamp DESC`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var eventos []RDPEvent
	for rows.Next() {
		var ev RDPEvent
		var tsStr string
		rows.Scan(&tsStr, &ev.EventID, &ev.Tipo, &ev.Usuario, &ev.IPOrigem, &ev.Computador, &ev.LogonType)
		ev.Timestamp, _ = time.Parse(time.RFC3339, tsStr)
		eventos = append(eventos, ev)
	}
	return eventos
}

var (
	modwtsapi32        = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSEnumSess    = modwtsapi32.NewProc("WTSEnumerateSessionsW")
	procWTSQuerySessInfo = modwtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory2 = modwtsapi32.NewProc("WTSFreeMemory")
)

func atualizarSessoesAtivas() {
	var pSessoes uintptr
	var count uint32

	ret, _, _ := procWTSEnumSess.Call(0, 0, 1,
		uintptr(unsafe.Pointer(&pSessoes)),
		uintptr(unsafe.Pointer(&count)),
	)
	if ret == 0 {
		return
	}
	defer procWTSFreeMemory2.Call(pSessoes)

	db.Exec(`UPDATE acessos SET ativa = 0 WHERE ativa = 1`)

	type wtsSessionInfo struct {
		SessionID         uint32
		WinStationName    *uint16
		State             uint32
	}

	size := unsafe.Sizeof(wtsSessionInfo{})
	for i := uint32(0); i < count; i++ {
		s := (*wtsSessionInfo)(unsafe.Pointer(pSessoes + uintptr(i)*size))
		// WTSActive = 0
		if s.State != 0 {
			continue
		}

		var pNome uintptr
		var nomeSize uint32
		// WTSUserName = 5
		ret, _, _ := procWTSQuerySessInfo.Call(
			0,
			uintptr(s.SessionID),
			5,
			uintptr(unsafe.Pointer(&pNome)),
			uintptr(unsafe.Pointer(&nomeSize)),
		)
		if ret == 0 || pNome == 0 {
			continue
		}

		usuario := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(pNome)))
		procWTSFreeMemory2.Call(pNome)

		if usuario == "" {
			continue
		}

		log.Printf("Sessão ATIVA: %s\n", usuario)
		db.Exec(`
			UPDATE acessos SET ativa = 1
			WHERE id = (
				SELECT id FROM acessos
				WHERE usuario = ?
				ORDER BY timestamp DESC LIMIT 1
			)`, usuario)
	}
}

func bloquearIP(ip string, tentativas int) {
	// Adiciona no banco
	db.Exec(`
		INSERT OR IGNORE INTO ips_bloqueados (ip, motivo, tentativas, bloqueado_em)
		VALUES (?, ?, ?, ?)`,
		ip,
		"Muitas tentativas de login falho",
		tentativas,
		time.Now().Format(time.RFC3339),
	)

	// Bloqueia no firewall do Windows
	nome := "RDPBlock-" + ip
	err := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+nome,
		"dir=in",
		"action=block",
		"protocol=any",
		"remoteip="+ip,
	).Run()
	if err != nil {
		log.Printf("Erro ao bloquear IP %s no firewall: %v\n", ip, err)
	} else {
		log.Printf("IP BLOQUEADO: %s (%d tentativas)\n", ip, tentativas)
	}
}

func desbloquearIP(ip string) {
	// Remove do banco
	db.Exec(`DELETE FROM ips_bloqueados WHERE ip = ?`, ip)

	// Remove do firewall
	nome := "RDPBlock-" + ip
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
		"name="+nome,
	).Run()

	log.Printf("IP DESBLOQUEADO: %s\n", ip)
}

func buscarIPsBloqueados() []struct {
	IP          string
	Tentativas  int
	BloqueadoEm time.Time
} {
	rows, err := db.Query(`
		SELECT ip, tentativas, bloqueado_em
		FROM ips_bloqueados
		ORDER BY bloqueado_em DESC`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var lista []struct {
		IP          string
		Tentativas  int
		BloqueadoEm time.Time
	}
	for rows.Next() {
		var item struct {
			IP          string
			Tentativas  int
			BloqueadoEm time.Time
		}
		var tsStr string
		rows.Scan(&item.IP, &item.Tentativas, &tsStr)
		item.BloqueadoEm, _ = time.Parse(time.RFC3339, tsStr)
		lista = append(lista, item)
	}
	return lista
}

func verificarBruteForce(ip string) {
	if ip == "" || ip == "-" {
		return
	}

	if ipEhConfiavel(ip) {
		return
	}

	// Conta total de falhas do IP — sem janela de tempo
	var count int
	db.QueryRow(`
		SELECT COUNT(*) FROM acessos
		WHERE ip_origem = ? AND evento_id = 4625`,
		ip,
	).Scan(&count)

	if count >= cfg.MaxTentativas {
		var existe int
		db.QueryRow(`SELECT COUNT(*) FROM ips_bloqueados WHERE ip = ?`, ip).Scan(&existe)
		if existe == 0 {
			bloquearIP(ip, count)
		}
	}
}