package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

func iniciarWeb() {
	http.HandleFunc("/", handlerPainel)
	http.HandleFunc("/api/acessos", handlerAPI)
	http.HandleFunc("/desbloquear", handlerDesbloquear)
	http.HandleFunc("/desconectar", handlerDesconectar)
	http.HandleFunc("/mensagem", handlerMensagem)
	log.Println("Painel web em http://localhost:8585")
	go http.ListenAndServe(":8585", nil)
}

func handlerAPI(w http.ResponseWriter, r *http.Request) {
	eventos := buscarAcessos(200)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("["))
	for i, ev := range eventos {
		if i > 0 {
			w.Write([]byte(","))
		}
		fmt.Fprintf(w, `{"timestamp":"%s","tipo":"%s","usuario":"%s","ip":"%s","computador":"%s","logon_type":"%s"}`,
			ev.Timestamp.Format("02/01/2006 15:04:05"),
			ev.Tipo, ev.Usuario, ev.IPOrigem, ev.Computador, ev.LogonType,
		)
	}
	w.Write([]byte("]"))
}

func handlerDesbloquear(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	desbloquearIP(ip)
	http.Redirect(w, r, "/", http.StatusFound)
}

func handlerPainel(w http.ResponseWriter, r *http.Request) {
	eventos := buscarAcessos(200)
	ativas := buscarSessoesAtivas()
	bloqueados := buscarIPsBloqueados()
	metricas := obterMetricas()

	// Deduplica
	type chaveEvento struct {
		usuario   string
		timestamp string
	}
	vistos := map[chaveEvento]bool{}
	var eventosFiltrados []RDPEvent
	for _, ev := range eventos {
		chave := chaveEvento{ev.Usuario, ev.Timestamp.Format("02/01/2006 15:04:05")}
		if vistos[chave] {
			continue
		}
		vistos[chave] = true
		eventosFiltrados = append(eventosFiltrados, ev)
	}
	eventos = eventosFiltrados

	total := len(eventos)
	rdp := 0
	falhas := 0
	for _, ev := range eventos {
		if ev.LogonType == "10" || ev.EventID == 21 {
			rdp++
		}
		if ev.EventID == 4625 {
			falhas++
		}
	}

	html := `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RDP Monitor</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family: 'Segoe UI', sans-serif; background:#0f1117; color:#e0e0e0; }

header {
	background: linear-gradient(135deg, #1a1d2e, #16213e);
	padding: 15px 30px;
	border-bottom: 2px solid #00d4ff;
	display: flex;
	align-items: center;
	justify-content: space-between;
}
header h1 { font-size: 20px; color:#00d4ff; }
header span { font-size:12px; color:#888; }

.layout {
	display: flex;
	gap: 0;
	height: calc(100vh - 57px);
}

/* COLUNA ESQUERDA */
.col-left {
	flex: 1;
	overflow-y: auto;
	padding: 20px;
	border-right: 1px solid #1a1d2e;
}

/* COLUNA DIREITA */
.col-right {
	width: 340px;
	min-width: 340px;
	overflow-y: auto;
	padding: 20px;
	background: #0d0f1a;
}

/* SESSOES ATIVAS */
.sessoes-ativas {
	background: #0d2b1a;
	border: 1px solid #00ff88;
	border-radius: 10px;
	padding: 12px 16px;
	margin-bottom: 15px;
}
.sessoes-ativas h2 { color:#00ff88; font-size:13px; margin-bottom:8px; }
.sessao-item {
	display: flex;
	gap: 12px;
	align-items: center;
	padding: 6px 0;
	border-bottom: 1px solid #0a1f12;
	font-size: 12px;
}
.sessao-item:last-child { border-bottom: none; }
.sessao-usuario { color:#00ff88; font-weight:bold; min-width:100px; }
.sessao-ip { font-family:monospace; color:#00d4ff; min-width:120px; }
.sessao-tempo { color:#888; font-size:11px; }
.nenhuma { color:#444; font-size:12px; }
.dot {
	width:7px; height:7px; border-radius:50%;
	background:#00ff88;
	box-shadow: 0 0 6px #00ff88;
	animation: pulse 1.5s infinite;
	flex-shrink: 0;
}
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }

/* IPS BLOQUEADOS */
.ips-bloqueados {
	background: #2b0d0d;
	border: 1px solid #ff4444;
	border-radius: 10px;
	padding: 12px 16px;
	margin-bottom: 15px;
}
.ips-bloqueados h2 { color:#ff4444; font-size:13px; margin-bottom:8px; }
.ip-item {
	display: flex;
	gap: 10px;
	align-items: center;
	padding: 6px 0;
	border-bottom: 1px solid #3d0000;
	font-size: 12px;
	flex-wrap: wrap;
}
.ip-item:last-child { border-bottom: none; }

/* STATS */
.stats {
	display: flex;
	gap: 10px;
	margin-bottom: 15px;
	flex-wrap: wrap;
}
.card {
	background: #1a1d2e;
	border: 1px solid #2a2d3e;
	border-radius: 10px;
	padding: 12px 18px;
	flex: 1;
	min-width: 100px;
}
.card .num { font-size: 26px; font-weight: bold; color:#00d4ff; }
.card .label { font-size: 11px; color:#888; margin-top:3px; }

/* TABELA */
.tabela-wrap { }
table { width:100%; border-collapse: collapse; }
thead tr { background:#1a1d2e; }
th { padding:10px 12px; text-align:left; font-size:11px; color:#888; text-transform:uppercase; letter-spacing:1px; border-bottom:1px solid #2a2d3e; }
td { padding:10px 12px; font-size:12px; border-bottom:1px solid #1a1d2e; }
tr:hover td { background:#1a1d2e; }

.badge { display:inline-block; padding:2px 8px; border-radius:20px; font-size:10px; font-weight:bold; }
.badge-rdp    { background:#003d1f; color:#00ff88; border:1px solid #00ff88; }
.badge-local  { background:#1a1a00; color:#ffcc00; border:1px solid #ffcc00; }
.badge-falha  { background:#3d0000; color:#ff4444; border:1px solid #ff4444; }
.badge-net    { background:#1a0033; color:#cc88ff; border:1px solid #cc88ff; }
.badge-logoff { background:#1a1a1a; color:#888888; border:1px solid #555555; }
.badge-outro  { background:#1a1a2e; color:#888; border:1px solid #444; }
.badge-sessao { background:#003d1f; color:#00ff88; border:1px solid #00ff88; }

.ip { font-family:monospace; color:#00d4ff; font-size:11px; }
.atualiza { font-size:11px; color:#555; margin-bottom:10px; }

/* METRICAS */
.metrica-titulo {
	font-size: 11px;
	color: #888;
	text-transform: uppercase;
	letter-spacing: 1px;
	margin-bottom: 12px;
	padding-bottom: 6px;
	border-bottom: 1px solid #1a1d2e;
}
.metrica-card {
	background: #1a1d2e;
	border: 1px solid #2a2d3e;
	border-radius: 10px;
	padding: 12px 15px;
	margin-bottom: 12px;
}
.metrica-card h3 { font-size: 11px; color:#888; margin-bottom:8px; text-transform:uppercase; }
.metrica-valor { font-size: 28px; font-weight: bold; color:#00d4ff; }
.metrica-sub { font-size: 11px; color:#666; margin-top:3px; }

.barra-wrap { margin-top: 6px; }
.barra-bg { background:#0f1117; border-radius:4px; height:6px; overflow:hidden; }
.barra-fill { height:6px; border-radius:4px; transition: width 0.3s; }
.barra-label { display:flex; justify-content:space-between; font-size:11px; color:#666; margin-top:3px; }

.disco-item { margin-bottom:10px; }
.disco-item:last-child { margin-bottom:0; }
.disco-nome { font-size:12px; color:#e0e0e0; margin-bottom:4px; }

.porta-item {
	display: flex;
	justify-content: space-between;
	align-items: center;
	padding: 5px 0;
	border-bottom: 1px solid #1a1d2e;
	font-size: 12px;
}
.porta-item:last-child { border-bottom: none; }
.porta-num { font-family:monospace; color:#00d4ff; font-weight:bold; }
.porta-estado-listen { color:#00ff88; font-size:10px; }
.porta-estado-estab { color:#ffcc00; font-size:10px; }

.uptime-val { font-size:16px; color:#00d4ff; font-weight:bold; }
</style>
</head>
<body>
<header>
	<div>
		<h1>RDP Monitor (v1.0)</h1>
		<span>Monitor de acessos em tempo real</span>
	</div>
	<span style="font-size:11px;color:#555;">` + time.Now().Format("02/01/2006 15:04:05") + ` — <a href="/" style="color:#00d4ff">Atualizar</a></span>
</header>

<div class="layout">
<!-- COLUNA ESQUERDA -->
<div class="col-left">
`

	// Sessões ativas
	html += `<div class="sessoes-ativas"><h2>&#9679; SESSOES ATIVAS AGORA</h2>`
	if len(ativas) == 0 {
		html += `<div class="nenhuma">Nenhuma sessao ativa no momento.</div>`
	} else {
		for _, ev := range ativas {
			ip := ev.IPOrigem
			if ip == "" || ip == "-" {
				ip = "—"
			}
			html += fmt.Sprintf(`
			<div class="sessao-item">
				<div class="dot"></div>
				<div class="sessao-usuario">%s</div>
				<div class="sessao-ip">%s</div>
				<div class="sessao-tempo">desde %s</div>
				<div style="margin-left:auto;display:flex;gap:6px;">
					<a href="/mensagem?usuario=%s&msg=O+servidor+sera+reiniciado+em+breve."
					   style="background:#1a1a00;color:#ffcc00;border:1px solid #ffcc00;padding:2px 8px;border-radius:20px;font-size:10px;text-decoration:none;">
					   Avisar
					</a>
					<a href="/desconectar?usuario=%s"
					   onclick="return confirm('Desconectar %s?')"
					   style="background:#3d0000;color:#ff4444;border:1px solid #ff4444;padding:2px 8px;border-radius:20px;font-size:10px;text-decoration:none;">
					   Desconectar
					</a>
				</div>
			</div>`, ev.Usuario, ip, ev.Timestamp.Format("02/01 15:04"),
				ev.Usuario, ev.Usuario, ev.Usuario)
		}
	}
	html += `</div>`

	// IPs bloqueados
	if len(bloqueados) > 0 {
		html += `<div class="ips-bloqueados"><h2>&#9632; IPS BLOQUEADOS</h2>`
		for _, b := range bloqueados {
			html += fmt.Sprintf(`
			<div class="ip-item">
				<span style="font-family:monospace;color:#ff4444;min-width:130px;">%s</span>
				<span style="color:#888;">%d tentativas</span>
				<span style="color:#555;font-size:11px;">desde %s</span>
				<a href="/desbloquear?ip=%s" style="background:#3d0000;color:#ff4444;border:1px solid #ff4444;padding:2px 10px;border-radius:20px;font-size:10px;text-decoration:none;margin-left:auto;">Desbloquear</a>
			</div>`,
				b.IP, b.Tentativas,
				b.BloqueadoEm.Format("02/01 15:04"),
				b.IP,
			)
		}
		html += `</div>`
	}

	// Stats
	html += fmt.Sprintf(`
<div class="stats">
	<div class="card"><div class="num">%d</div><div class="label">Total eventos</div></div>
	<div class="card"><div class="num" style="color:#00ff88">%d</div><div class="label">Acessos RDP</div></div>
	<div class="card"><div class="num" style="color:#ff4444">%d</div><div class="label">Falhas login</div></div>
	<div class="card"><div class="num" style="color:#00ff88">%d</div><div class="label">Sessoes ativas</div></div>
</div>
`, total, rdp, falhas, len(ativas))

	// Tabela
	html += `<div class="tabela-wrap">
<table>
<thead>
	<tr>
		<th>Data/Hora</th>
		<th>Tipo</th>
		<th>Usuario</th>
		<th>IP Origem</th>
		<th>Computador</th>
	</tr>
</thead>
<tbody>`

	if len(eventos) == 0 {
		html += `<tr><td colspan="5" style="text-align:center;padding:40px;color:#444">Nenhum evento registrado ainda.</td></tr>`
	}

	for _, ev := range eventos {
		badge := ""
		switch {
		case ev.EventID == 21:
			badge = `<span class="badge badge-sessao">SESSAO</span>`
		case ev.EventID == 25:
			badge = `<span class="badge badge-net">RECONECT</span>`
		case ev.LogonType == "10":
			badge = `<span class="badge badge-rdp">RDP</span>`
		case ev.EventID == 4625:
			badge = `<span class="badge badge-falha">FALHA</span>`
		case ev.Tipo == "LOGOFF":
			badge = `<span class="badge badge-logoff">LOGOFF</span>`
		case ev.LogonType == "3":
			badge = `<span class="badge badge-net">NET</span>`
		case ev.LogonType == "2":
			badge = `<span class="badge badge-local">LOCAL</span>`
		case ev.LogonType == "7":
			badge = `<span class="badge badge-local">UNLOCK</span>`
		default:
			badge = `<span class="badge badge-outro">` + ev.LogonType + `</span>`
		}

		ip := ev.IPOrigem
		if ip == "" || ip == "-" {
			ip = `<span style="color:#444">—</span>`
		} else {
			ip = `<span class="ip">` + ip + `</span>`
		}

		html += fmt.Sprintf(`
<tr>
	<td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>
</tr>`,
			ev.Timestamp.Format("02/01/2006 15:04:05"),
			badge, ev.Usuario, ip, ev.Computador,
		)
	}

	html += `</tbody></table></div>
</div><!-- fim col-left -->

<!-- COLUNA DIREITA — METRICAS -->
<div class="col-right">
<div class="metrica-titulo">&#9881; SERVIDOR</div>
`

	// CPU
	cpuCor := "#00d4ff"
	if metricas.CPUPercent > 80 {
		cpuCor = "#ff4444"
	} else if metricas.CPUPercent > 60 {
		cpuCor = "#ffcc00"
	}
	html += fmt.Sprintf(`
<div class="metrica-card">
	<h3>CPU</h3>
	<div class="metrica-valor" style="color:%s">%.1f%%</div>
	<div class="barra-wrap">
		<div class="barra-bg"><div class="barra-fill" style="width:%.1f%%;background:%s;"></div></div>
	</div>
</div>`, cpuCor, metricas.CPUPercent, metricas.CPUPercent, cpuCor)

	// Memória
	memCor := "#00d4ff"
	if metricas.MemPercent > 85 {
		memCor = "#ff4444"
	} else if metricas.MemPercent > 70 {
		memCor = "#ffcc00"
	}
	html += fmt.Sprintf(`
<div class="metrica-card">
	<h3>Memoria RAM</h3>
	<div class="metrica-valor" style="color:%s">%.1f%%</div>
	<div class="barra-wrap">
		<div class="barra-bg"><div class="barra-fill" style="width:%.1f%%;background:%s;"></div></div>
		<div class="barra-label"><span>%s usado</span><span>%s total</span></div>
	</div>
</div>`, memCor, metricas.MemPercent, metricas.MemPercent, memCor,
		formatBytes(metricas.MemUsada), formatBytes(metricas.MemTotal))

	// Uptime
	html += fmt.Sprintf(`
<div class="metrica-card">
	<h3>Uptime</h3>
	<div class="uptime-val">%s</div>
</div>`, metricas.Uptime)

	// Discos
	if len(metricas.Discos) > 0 {
		html += `<div class="metrica-card"><h3>Disco</h3>`
		for _, d := range metricas.Discos {
			discoCor := "#00d4ff"
			if d.Percentual > 90 {
				discoCor = "#ff4444"
			} else if d.Percentual > 75 {
				discoCor = "#ffcc00"
			}
			html += fmt.Sprintf(`
<div class="disco-item">
	<div class="disco-nome">%s — <span style="color:%s">%.1f%%</span> <span style="color:#555;font-size:11px;">(%s livre de %s)</span></div>
	<div class="barra-bg"><div class="barra-fill" style="width:%.1f%%;background:%s;"></div></div>
</div>`, d.Letra, discoCor, d.Percentual, formatBytes(d.Livre), formatBytes(d.Total), d.Percentual, discoCor)
		}
		html += `</div>`
	}

	// Portas abertas
	if len(metricas.PortasAbertas) > 0 {
		html += `<div class="metrica-card"><h3>Portas Abertas</h3>`
		nomePorta := map[string]string{
			"3389": "RDP", "8585": "RDP Monitor", "80": "HTTP",
			"443": "HTTPS", "445": "SMB", "135": "RPC",
			"22": "SSH", "21": "FTP", "25": "SMTP",
		}
		for _, p := range metricas.PortasAbertas {
			nome := nomePorta[p.Porta]
			if nome == "" {
				nome = p.Porta
			}
			estadoClass := "porta-estado-listen"
			if p.Estado == "ESTABLISHED" {
				estadoClass = "porta-estado-estab"
			}
			html += fmt.Sprintf(`
<div class="porta-item">
	<span class="porta-num">:%s</span>
	<span style="color:#888;font-size:11px;">%s</span>
	<span class="%s">%s</span>
</div>`, p.Porta, nome, estadoClass, p.Estado)
		}
		html += `</div>`
	}

	html += `</div><!-- fim col-right -->
</div><!-- fim layout -->
<script>setTimeout(()=>location.reload(), 30000)</script>
</body></html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}


func handlerDesconectar(w http.ResponseWriter, r *http.Request) {
	usuario := r.URL.Query().Get("usuario")
	if usuario != "" {
		desconectarUsuario(usuario)
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func handlerMensagem(w http.ResponseWriter, r *http.Request) {
	usuario := r.URL.Query().Get("usuario")
	msg := r.URL.Query().Get("msg")
	if msg == "" {
		msg = "Aviso do administrador do servidor."
	}
	if usuario != "" {
		enviarMensagem(usuario, "Aviso do Administrador", msg)
	}
	http.Redirect(w, r, "/", http.StatusFound)
}