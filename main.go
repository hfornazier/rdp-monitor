package main

import (
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type EventXML struct {
	XMLName   xml.Name     `xml:"Event"`
	System    SystemXML    `xml:"System"`
	EventData EventDataXML `xml:"EventData"`
	UserData  UserDataXML  `xml:"UserData"`
}

type SystemXML struct {
	EventID     uint32 `xml:"EventID"`
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"TimeCreated"`
	Computer string `xml:"Computer"`
}

type EventDataXML struct {
	Data []DataXML `xml:"Data"`
}

type DataXML struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

type UserDataXML struct {
	EventXML UserDataEventXML `xml:"EventXML"`
}

type UserDataEventXML struct {
	User      string `xml:"User"`
	Address   string `xml:"Address"`
	SessionID string `xml:"SessionID"`
}

type RDPEvent struct {
	Timestamp  time.Time
	EventID    uint32
	Usuario    string
	IPOrigem   string
	Computador string
	Tipo       string
	LogonType  string
}

var (
	modwevtapi    = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery  = modwevtapi.NewProc("EvtQuery")
	procEvtNext   = modwevtapi.NewProc("EvtNext")
	procEvtRender = modwevtapi.NewProc("EvtRender")
	procEvtClose  = modwevtapi.NewProc("EvtClose")
)

const (
	EvtQueryChannelPath      = 0x1
	EvtQueryReverseDirection = 0x200
	EvtRenderEventXml        = 1
)

func queryEventLog(canal string, xpath string) ([]string, error) {
	agora := time.Now().UTC()
	umaHoraAtras := agora.Add(-1 * time.Hour).Format("2006-01-02T15:04:05.000Z")

	xpathComTempo := fmt.Sprintf(
		"*[System[(%s) and TimeCreated[@SystemTime>='%s']]]",
		extrairFiltroEventID(xpath),
		umaHoraAtras,
	)

	cCanal, _ := windows.UTF16PtrFromString(canal)
	cXPath, _ := windows.UTF16PtrFromString(xpathComTempo)

	hQuery, _, err := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(cCanal)),
		uintptr(unsafe.Pointer(cXPath)),
		EvtQueryChannelPath|EvtQueryReverseDirection,
	)
	if hQuery == 0 {
		return nil, fmt.Errorf("EvtQuery falhou: %v", err)
	}
	defer procEvtClose.Call(hQuery)

	var resultados []string
	handles := make([]windows.Handle, 20)
	var retornados uint32

	for {
		ret, _, _ := procEvtNext.Call(
			hQuery,
			uintptr(len(handles)),
			uintptr(unsafe.Pointer(&handles[0])),
			0, 0,
			uintptr(unsafe.Pointer(&retornados)),
		)
		if ret == 0 || retornados == 0 {
			break
		}
		for i := uint32(0); i < retornados; i++ {
			x := renderEventXML(handles[i])
			if x != "" {
				resultados = append(resultados, x)
			}
			procEvtClose.Call(uintptr(handles[i]))
		}
	}
	return resultados, nil
}

func extrairFiltroEventID(xpath string) string {
	inicio := strings.Index(xpath, "[(") + 2
	fim := strings.LastIndex(xpath, ")]]")
	if inicio > 2 && fim > inicio {
		return xpath[inicio:fim]
	}
	return xpath
}

func renderEventXML(hEvent windows.Handle) string {
	var bufUsed, propCount uint32
	procEvtRender.Call(0, uintptr(hEvent), EvtRenderEventXml, 0, 0,
		uintptr(unsafe.Pointer(&bufUsed)),
		uintptr(unsafe.Pointer(&propCount)),
	)
	if bufUsed == 0 {
		return ""
	}
	buf := make([]uint16, bufUsed)
	ret, _, _ := procEvtRender.Call(0, uintptr(hEvent), EvtRenderEventXml,
		uintptr(bufUsed),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufUsed)),
		uintptr(unsafe.Pointer(&propCount)),
	)
	if ret == 0 {
		return ""
	}
	return windows.UTF16ToString(buf)
}

func parsearEvento(xmlStr string) (*RDPEvent, error) {
	var ev EventXML
	if err := xml.Unmarshal([]byte(xmlStr), &ev); err != nil {
		return nil, err
	}

	campos := map[string]string{}
	for _, d := range ev.EventData.Data {
		campos[d.Name] = d.Value
	}

	ts, _ := time.Parse("2006-01-02T15:04:05.999999999Z", ev.System.TimeCreated.SystemTime)
	ts = ts.Local()

	rdp := &RDPEvent{
		Timestamp:  ts,
		EventID:    ev.System.EventID,
		Computador: ev.System.Computer,
		Usuario:    campos["TargetUserName"],
		IPOrigem:   campos["IpAddress"],
		LogonType:  campos["LogonType"],
	}

	if rdp.Usuario == "" {
		rdp.Usuario = campos["User"]
	}
	if rdp.IPOrigem == "" {
		rdp.IPOrigem = campos["Address"]
	}

	// Para eventos do canal TerminalServices (UserData)
	if rdp.Usuario == "" {
		rdp.Usuario = ev.UserData.EventXML.User
	}
	if rdp.IPOrigem == "" {
		rdp.IPOrigem = ev.UserData.EventXML.Address
	}

	// Remove domínio do usuário ex: "Tennessee\Humberto" -> "Humberto"
	if strings.Contains(rdp.Usuario, "\\") {
		partes := strings.SplitN(rdp.Usuario, "\\", 2)
		rdp.Usuario = partes[1]
	}

	// Para logoff garante usuario preenchido
	if ev.System.EventID == 4634 || ev.System.EventID == 4647 {
		if rdp.Usuario == "" {
			rdp.Usuario = campos["TargetUserName"]
		}
	}

	switch ev.System.EventID {
	case 21:
		rdp.Tipo = "SESSÃO INICIADA"
	case 23:
		rdp.Tipo = "LOGOFF"
	case 24:
		rdp.Tipo = "DESCONECTOU"
	case 25:
		rdp.Tipo = "RECONECTOU"
	case 4624:
		if campos["LogonType"] == "10" {
			rdp.Tipo = "LOGIN REMOTO"
		} else {
			rdp.Tipo = "LOGIN LOCAL"
		}
	case 4625:
		rdp.Tipo = "FALHA DE LOGIN"
	case 4634, 4647:
		rdp.Tipo = "LOGOFF"
	}

	return rdp, nil
}

func exibirEvento(ev *RDPEvent) {
	if ev.Usuario == "" || ev.Usuario == "-" {
		return
	}

	ignorarUsuarios := []string{
		"SISTEMA", "SYSTEM", "SERVIÇO LOCAL", "LOCAL SERVICE",
		"SERVIÇO DE REDE", "NETWORK SERVICE", "-", "",
		"defaultuser0", "defaultuser1",
	}
	for _, u := range ignorarUsuarios {
		if strings.EqualFold(ev.Usuario, u) {
			return
		}
	}

	prefixosIgnorar := []string{"DWM-", "UMFD-", "ANONYMOUS"}
	for _, p := range prefixosIgnorar {
		if strings.HasPrefix(strings.ToUpper(ev.Usuario), p) {
			return
		}
	}

	if ev.LogonType == "5" || ev.LogonType == "0" || ev.LogonType == "2" {
		return
	}

	if ev.Tipo == "" {
		return
	}

	descricao := ev.Tipo
	switch ev.LogonType {
	case "7":
		descricao = "DESBLOQUEIO DE TELA"
	case "10":
		descricao = "LOGIN REMOTO (RDP)"
	case "11":
		descricao = "LOGIN COM CACHE"
	}

	fmt.Println("┌─────────────────────────────────────────")
	fmt.Printf("│ [v4.0] %s\n", descricao)
	fmt.Printf("│ %s\n", ev.Timestamp.Format("02/01/2006 15:04:05"))
	fmt.Printf("│ Usuario:    %s\n", ev.Usuario)
	if ev.IPOrigem != "" && ev.IPOrigem != "-" {
		fmt.Printf("│ IP Origem:  %s\n", ev.IPOrigem)
	}
	fmt.Printf("│ Computador: %s\n", ev.Computador)
	fmt.Println("└─────────────────────────────────────────")
}

func monitorar() {
	carregarConfig()
	iniciarDB()
	iniciarWeb()
	log.Println("RDP Monitor ativo — monitorando eventos...")
	fmt.Println("═══════════════════════════════════════════")
	vistos := map[string]bool{}
	canais := []struct {
		canal string
		xpath string
	}{
		{
			"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
			"*[System[(EventID=21 or EventID=23 or EventID=24 or EventID=25)]]",
		},
		{
			"Security",
			"*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647)]]",
		},
	}

	for {
		atualizarSessoesAtivas()

		for _, c := range canais {
			xmls, err := queryEventLog(c.canal, c.xpath)
			if err != nil {
				log.Printf("Erro: %v\n", err)
				continue
			}
			for _, x := range xmls {
				ev, err := parsearEvento(x)
				if err != nil {
					continue
				}
				chave := fmt.Sprintf("%d|%s|%s", ev.EventID, ev.Usuario, ev.Timestamp.String())
				if vistos[chave] {
					continue
				}
				vistos[chave] = true
				exibirEvento(ev)
				if ev.EventID == 4634 || ev.EventID == 4647 || ev.EventID == 23 {
					if ev.Usuario != "" && ev.Usuario != "-" {
						encerrarSessao(ev.Usuario, ev.Timestamp)
					}
				} else {
					salvarEvento(ev)
					// Verifica brute force em falhas de login
					if ev.EventID == 4625 && ev.IPOrigem != "" {
						verificarBruteForce(ev.IPOrigem)
					}
				}
			}
		}
		time.Sleep(10 * time.Second)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("RDP Monitor v1.0")
		fmt.Println("Uso: rdp-monitor [comando]")
		fmt.Println("Comandos:")
		fmt.Println("  start          - Roda em modo console")
		fmt.Println("  install        - Instala como servico Windows")
		fmt.Println("  uninstall      - Remove o servico")
		fmt.Println("  start-service  - Inicia o servico")
		fmt.Println("  stop-service   - Para o servico")
		fmt.Println("  service        - Modo servico (usado internamente)")
		fmt.Println("\nPressione ENTER para sair...")
		fmt.Scanln()
		return
	}

	switch os.Args[1] {
	case "start":
		fmt.Println("RDP Monitor v2.0 iniciando em modo console...")
		monitorar()
	case "install":
		instalarServico()
	case "uninstall":
		desinstalarServico()
	case "start-service":
		iniciarServico()
	case "stop-service":
		pararServico()
	case "service":
		rodarComoServico()
	default:
		fmt.Println("Comando desconhecido:", os.Args[1])
	}
}