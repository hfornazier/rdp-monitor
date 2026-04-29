# 🖥️ RDP Monitor

Monitor de acessos RDP para Windows com painel web em tempo real.

## 📋 Funcionalidades

- ✅ **Sessões ativas em tempo real** — quem está conectado agora, com IP e horário
- ✅ **Histórico de acessos** — todos os logins, logoffs e reconexões
- ✅ **Proteção contra Brute Force** — bloqueia IPs automaticamente após X tentativas
- ✅ **Gerenciamento de sessões** — desconecta usuários e envia mensagens pelo painel
- ✅ **Métricas do servidor** — CPU, memória, disco, uptime e portas abertas
- ✅ **Painel web** — acesse de qualquer navegador na rede
- ✅ **Serviço Windows** — inicia automaticamente com o servidor
- ✅ **Zero dependências** — um único executável, sem instalar nada

## 🚀 Instalação

### Pré-requisitos
- Windows 8 / 10 / 11 / Server 2012+
- Nenhuma dependência externa necessária

### Passos

**1. Baixe o executável** na página de [Releases](https://github.com/hfornazier/rdp-monitor/releases)

**2. Crie a pasta** no servidor:
C:\rdp-monitor\

**3. Copie** o `rdp-monitor.exe` para a pasta

**4. Configure** criando o arquivo `config.ini` na mesma pasta:
```ini
[seguranca]
max_tentativas = 3

[ips_confiaveis]
127.0.0.1
# Adicione seu IP aqui para nunca ser bloqueado!
# 192.168.1.100
```

**5. Instale como serviço** (cmd como Administrador):
```cmd
cd C:\rdp-monitor
rdp-monitor install
rdp-monitor start-service
```

**6. Libere a porta** no firewall:
```cmd
netsh advfirewall firewall add rule name="RDP Monitor Web" dir=in action=allow protocol=TCP localport=8585
```

**7. Acesse o painel:**
http://localhost:8585
http://SEU-IP:8585

## 🔧 Comandos

```cmd
rdp-monitor install        # Instala como serviço Windows
rdp-monitor start-service  # Inicia o serviço
rdp-monitor stop-service   # Para o serviço
rdp-monitor uninstall      # Remove o serviço
rdp-monitor start          # Roda em modo console (para testes)
```

## ⚙️ Configuração (config.ini)

```ini
[seguranca]
# Número de tentativas de login antes de bloquear o IP
max_tentativas = 3

[ips_confiaveis]
# IPs que NUNCA serão bloqueados
127.0.0.1
# 192.168.1.100
# 187.84.244.156
```

> ⚠️ **Importante:** Adicione seu IP em `ips_confiaveis` antes de ativar
> para não correr risco de se bloquear!

## 📊 Painel Web

O painel exibe em tempo real:

| Seção | Informações |
|---|---|
| Sessões Ativas | Usuário, IP, horário de conexão |
| IPs Bloqueados | IP, tentativas, botão desbloquear |
| Histórico | Todos os eventos com badges coloridos |
| Servidor | CPU, RAM, disco, uptime, portas |

### Badges de eventos

| Badge | Significado |
|---|---|
| 🟢 `SESSAO` | Sessão RDP iniciada |
| 🟢 `RDP` | Login remoto bem-sucedido |
| 🟣 `RECONECT` | Reconexão de sessão |
| 🟣 `NET` | Autenticação de rede |
| 🔴 `FALHA` | Tentativa de login falhou |
| ⚫ `LOGOFF` | Usuário desconectou |

## 🛡️ Proteção Brute Force

O sistema monitora tentativas de login falhas (EventID 4625).
Quando um IP atinge o limite configurado em `max_tentativas`, ele é:

1. **Bloqueado no firewall** do Windows automaticamente (todo o tráfego do IP)
2. **Registrado no banco** com data, hora e número de tentativas
3. **Exibido no painel** com botão para desbloquear manualmente

## 🔨 Compilar do código-fonte

Requer [Go 1.21+](https://golang.org/dl/)

```bash
git clone https://github.com/hfornazier/rdp-monitor.git
cd rdp-monitor
go mod tidy

# Compilar para Windows 64-bit
set GOARCH=amd64
set GOOS=windows
go build -o rdp-monitor.exe .

# Compilar para Windows 32-bit
set GOARCH=386
set GOOS=windows
go build -o rdp-monitor-x86.exe .
```

## 📁 Estrutura do projeto
rdp-monitor/
├── main.go        # Ponto de entrada e monitor de eventos
├── db.go          # Banco de dados SQLite e funções de bloqueio
├── web.go         # Painel web e handlers HTTP
├── metricas.go    # Métricas do sistema via API Windows
├── servico.go     # Integração com Windows Service Manager
├── config.go      # Leitura do config.ini
├── go.mod
└── go.sum

## 🤝 Contribuindo

Pull requests são bem-vindos! Para mudanças grandes, abra uma issue primeiro.

## 📄 Licença

MIT — veja [LICENSE](LICENSE) para detalhes.

---

Desenvolvido com ❤️ e Go
