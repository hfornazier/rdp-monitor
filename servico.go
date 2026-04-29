package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const nomeServico = "RDPMonitor"
const descServico = "Monitor de acessos RDP em tempo real"

type rdpService struct{}

func (s *rdpService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	go monitorar()

	changes <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}

	for c := range r {
		switch c.Cmd {
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			return false, 0
		}
	}
	return false, 0
}

func instalarServico() {
	exePath, err := filepath.Abs(os.Args[0])
	if err != nil {
		log.Fatal("Erro ao obter caminho do exe:", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		log.Fatal("Erro ao conectar ao SCM:", err)
	}
	defer m.Disconnect()

	s, err := m.CreateService(nomeServico, exePath,
		mgr.Config{
			StartType:   mgr.StartAutomatic,
			DisplayName: "RDP Monitor",
			Description: descServico,
		},
		"service",
	)
	if err != nil {
		log.Fatal("Erro ao criar serviço:", err)
	}
	defer s.Close()

	fmt.Println("✅ Serviço instalado com sucesso!")
	fmt.Println("Para iniciar: rdp-monitor start-service")
}

func desinstalarServico() {
	m, err := mgr.Connect()
	if err != nil {
		log.Fatal("Erro ao conectar ao SCM:", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(nomeServico)
	if err != nil {
		log.Fatal("Serviço não encontrado:", err)
	}
	defer s.Close()

	err = s.Delete()
	if err != nil {
		log.Fatal("Erro ao remover serviço:", err)
	}
	fmt.Println("✅ Serviço removido com sucesso!")
}

func iniciarServico() {
	m, err := mgr.Connect()
	if err != nil {
		log.Fatal("Erro ao conectar ao SCM:", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(nomeServico)
	if err != nil {
		log.Fatal("Serviço não encontrado:", err)
	}
	defer s.Close()

	err = s.Start()
	if err != nil {
		log.Fatal("Erro ao iniciar serviço:", err)
	}
	fmt.Println("✅ Serviço iniciado!")
}

func pararServico() {
	m, err := mgr.Connect()
	if err != nil {
		log.Fatal("Erro ao conectar ao SCM:", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(nomeServico)
	if err != nil {
		log.Fatal("Serviço não encontrado:", err)
	}
	defer s.Close()

	s.Control(svc.Stop)
	fmt.Println("✅ Serviço parado!")
}

func rodarComoServico() {
	err := svc.Run(nomeServico, &rdpService{})
	if err != nil {
		log.Fatal("Erro ao rodar como serviço:", err)
	}
}