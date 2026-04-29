package main

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	MaxTentativas  int
	JanelaMinutos  int
	IPsConfiaveis  []string
}

var cfg Config

func carregarConfig() {
	// Valores padrão
	cfg = Config{
		MaxTentativas: 5,
		JanelaMinutos: 5,
		IPsConfiaveis: []string{"127.0.0.1"},
	}

	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	configPath := filepath.Join(exeDir, "config.ini")

	// Se não existe, cria com valores padrão
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		criarConfigPadrao(configPath)
		return
	}

	file, err := os.Open(configPath)
	if err != nil {
		log.Println("Erro ao abrir config.ini:", err)
		return
	}
	defer file.Close()

	secao := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		linha := strings.TrimSpace(scanner.Text())

		// Ignora comentários e linhas vazias
		if linha == "" || strings.HasPrefix(linha, "#") {
			continue
		}

		// Seção
		if strings.HasPrefix(linha, "[") && strings.HasSuffix(linha, "]") {
			secao = strings.ToLower(linha[1 : len(linha)-1])
			continue
		}

		switch secao {
		case "seguranca":
			partes := strings.SplitN(linha, "=", 2)
			if len(partes) != 2 {
				continue
			}
			chave := strings.TrimSpace(partes[0])
			valor := strings.TrimSpace(partes[1])
			switch chave {
			case "max_tentativas":
				if v, err := strconv.Atoi(valor); err == nil {
					cfg.MaxTentativas = v
				}
			case "janela_minutos":
				if v, err := strconv.Atoi(valor); err == nil {
					cfg.JanelaMinutos = v
				}
			}
		case "ips_confiaveis":
			if linha != "" {
				cfg.IPsConfiaveis = append(cfg.IPsConfiaveis, linha)
			}
		}
	}

	log.Printf("Config carregada: max=%d tentativas, janela=%d min, IPs confiaveis=%v\n",
		cfg.MaxTentativas, cfg.JanelaMinutos, cfg.IPsConfiaveis)
}

func criarConfigPadrao(path string) {
	conteudo := `# RDP Monitor - Configuracao
# Edite este arquivo e reinicie o servico

[seguranca]
# Numero maximo de tentativas de login antes de bloquear o IP
max_tentativas = 3

[ips_confiaveis]
# IPs que NUNCA serao bloqueados (um por linha)
# Adicione seu IP aqui para nao correr risco de se bloquear!
127.0.0.1
`
	os.WriteFile(path, []byte(conteudo), 0644)
	log.Println("config.ini criado com valores padrão!")
}

func ipEhConfiavel(ip string) bool {
	for _, ipConfiavel := range cfg.IPsConfiaveis {
		if ip == ipConfiavel {
			return true
		}
	}
	return false
}