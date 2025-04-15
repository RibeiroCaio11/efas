import streamlit as st
import pandas as pd
import plotly.express as px
import time
from datetime import datetime
import random
import platform
import subprocess

class SecurityUI:
    """Classe para gerenciar a interface do usuário do sistema de segurança"""
    
    def __init__(self, config, logger, network_monitor, security_agent, threat_intel):
        self.config = config
        self.logger = logger
        self.network_monitor = network_monitor
        self.security_agent = security_agent
        self.threat_intel = threat_intel
    
    def run(self):
        """Iniciar a interface Streamlit"""
        # Configurações da página
        st.set_page_config(page_title="Agente Autônomo de Segurança", layout="wide")
        
        # Inicializar estado da sessão
        self._initialize_session_state()
        
        # Simulação automática de ataques
        if st.session_state.simulation_active:
            self._auto_simulate_attack()
        
        # Renderizar componentes da UI
        self._render_header()
        self._render_simulation_control()
        self._render_metrics()
        self._render_controls()
        self._render_mcp()
        self._render_logs()
        self._render_sidebar()
        self._render_threat_intelligence()
        
        # Atualização automática a cada 5 segundos
        time.sleep(5)  # Esperar 5 segundos
        st.rerun()  # Atualizar a página automaticamente
    
    def _initialize_session_state(self):
        """Inicializa todos os estados da sessão diretamente"""
        if "blocked_ips" not in st.session_state:
            st.session_state.blocked_ips = set()
        if "threat_stats" not in st.session_state:
            st.session_state.threat_stats = {'high': 0, 'medium': 0, 'low': 0}
        if "activity_log" not in st.session_state:
            st.session_state.activity_log = []
        if "monitoring_active" not in st.session_state:
            st.session_state.monitoring_active = True
        if "simulation_active" not in st.session_state:
            st.session_state.simulation_active = True
        if "monitoring_cycles" not in st.session_state:
            st.session_state.monitoring_cycles = 0
        if "last_attack_time" not in st.session_state:
            st.session_state.last_attack_time = 0
        if "mcp_context" not in st.session_state:
            st.session_state.mcp_context = {
                "contexto_ameaças": "Monitorando padrões de tráfego",
                "última_atualização": datetime.now().strftime("%H:%M:%S"),
                "nível_confiança": 85,
                "estado_análise": "Ativo",
                "análises_pendentes": 0,
                "eventos_correlacionados": [],
                "padrões_identificados": []
            }
    
    def _render_simulation_control(self):
        """Renderiza o controle para ligar/desligar a simulação"""
        col1, col2 = st.columns([4, 1])
        with col1:
            st.markdown("### Status da Simulação:")
        with col2:
            simulation_state = "Ativa" if st.session_state.simulation_active else "Inativa"
            button_label = "Desativar Simulação" if st.session_state.simulation_active else "Ativar Simulação"
            button_color = "🔴" if st.session_state.simulation_active else "🟢"
            
            if st.button(f"{button_color} {button_label}", use_container_width=True):
                st.session_state.simulation_active = not st.session_state.simulation_active
                if st.session_state.simulation_active:
                    self.logger.log_activity("Simulação de ataques ativada", "success")
                else:
                    self.logger.log_activity("Simulação de ataques desativada", "warning")
                st.rerun()
                
        status_color = "success" if st.session_state.simulation_active else "warning"
        status_msg = "✅ Simulação de ataques está ATIVA - Ataques simulados a cada 7 segundos" if st.session_state.simulation_active else "⚠️ Simulação de ataques está INATIVA - Nenhum ataque será simulado"
        st.markdown(f":{status_color}[{status_msg}]")
    
    def _auto_simulate_attack(self):
        """Simulação automática de ataques"""
        current_time = time.time()
        
        # Verificar se é o primeiro carregamento da página
        first_load = False
        if "last_page_load" not in st.session_state:
            st.session_state.last_page_load = current_time
            first_load = True
            
        # Simular ataques em sequência no primeiro carregamento
        if first_load:
            # Gerar 3 ataques iniciais (1 de cada tipo)
            self._simulate_attack_by_level("high")
            self._simulate_attack_by_level("medium")
            self._simulate_attack_by_level("low")
            st.session_state.last_attack_time = current_time
            
        # Realizar ciclo de monitoramento a cada 10 segundos
        if "last_monitoring_time" not in st.session_state:
            st.session_state.last_monitoring_time = 0
            
        if current_time - st.session_state.last_monitoring_time >= 10:
            self.network_monitor.start_monitoring()
            st.session_state.last_monitoring_time = current_time
        
        # Simular um ataque a cada 7 segundos
        if current_time - st.session_state.last_attack_time >= 7:
            self._simulate_random_attack()
            st.session_state.last_attack_time = current_time
            
        # Correlação automática de eventos a cada 15 segundos
        if "last_correlation_time" not in st.session_state:
            st.session_state.last_correlation_time = 0
            
        if current_time - st.session_state.last_correlation_time >= 15:
            # Verificar se há eventos suficientes para correlacionar
            if len(self.logger.get_recent_logs(10)) >= 3:
                self._correlate_events(automatic=True)
                st.session_state.last_correlation_time = current_time
            
    def _simulate_attack_by_level(self, risk_level):
        """Simula um ataque de nível específico (alto, médio ou baixo)"""
        # Lista de IPs por categoria de risco
        high_risk_ips = [
            "192.168.1." + str(random.randint(1, 254)),
            "10.0.0." + str(random.randint(1, 254)),
            "172.16.0." + str(random.randint(1, 254))
        ]
        
        medium_risk_ips = [
            "8.8.8." + str(random.randint(1, 254)),
            "1.1.1." + str(random.randint(1, 254)),
            "208.67.222." + str(random.randint(1, 254))
        ]
        
        low_risk_ips = [
            "216.58.215." + str(random.randint(1, 254)),
            "151.101." + str(random.randint(1, 254)),
            "13.32." + str(random.randint(1, 254))
        ]
        
        # Configurar com base no nível solicitado
        if risk_level == "high":
            selected_ip = random.choice(high_risk_ips)
            risk_text = "ALTO"
            log_type = 'error'
            threat_types = ["Tentativa de Acesso Não Autorizado", "Execução de Código Remoto", "Ataque de Força Bruta"]
            threat_details = ["Padrão de ataque conhecido detectado", "Tráfego malicioso detectado"]
        elif risk_level == "medium":
            selected_ip = random.choice(medium_risk_ips)
            risk_text = "MÉDIO"
            log_type = 'warning'
            threat_types = ["Atividade de Rede Suspeita", "Transferência Incomum de Dados", "Conexão Suspeita"]
            threat_details = ["Padrão de tráfego incomum", "Tráfego suspeito detectado"]
        else:  # baixo
            selected_ip = random.choice(low_risk_ips)
            risk_text = "BAIXO"
            log_type = 'info'
            threat_types = ["Atividade Incomum", "Acesso a Recursos Sensíveis", "Comportamento Fora de Padrão"]
            threat_details = ["Possível falso positivo", "Comportamento incomum detectado"]
        
        # Seleciona protocolos e portas
        protocol = random.choice(["TCP", "UDP", "HTTP", "HTTPS", "DNS"])
        port = random.randint(1, 65535)
        
        # Registra o alerta
        log_message = f"⚠️ ATAQUE SIMULADO: {random.choice(threat_types)} de {selected_ip}:{port} via {protocol} - Risco {risk_text}"
        self.logger.log_activity(log_message, log_type)
        
        # Envia para análise no security agent
        threat_data = {
            "ip": selected_ip,
            "type": random.choice(threat_types),
            "details": random.choice(threat_details),
            "timestamp": datetime.now().isoformat(),
            "risk_level": risk_level
        }
        
        # Analisar a ameaça
        self.security_agent.analyze_threat(threat_data)
    
    def _render_header(self):
        """Renderiza o cabeçalho da aplicação"""
        st.title("🤖 Agente Autônomo de Segurança Cibernética")
        
        # Esconder botões de simulação manual já que agora é automático
        if st.checkbox("📊 Mostrar Controles Manuais", value=False):
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔄 Forçar Ciclo de Monitoramento", use_container_width=True):
                    self.network_monitor.start_monitoring()
            
            with col2:
                if st.button("⚠️ Forçar Detecção de Ameaça", use_container_width=True):
                    self._simulate_random_attack()
    
    def _render_metrics(self):
        """Renderiza métricas principais"""
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("IPs Bloqueados", len(st.session_state.blocked_ips))
        col2.metric("IPs em Monitoramento", len(st.session_state.get("monitored_ips", set())))
        col3.metric("IPs em Honeypot", len(st.session_state.get("honeypot_ips", set())))
        col4.metric("Ciclos de Monitoramento", st.session_state.get("monitoring_cycles", 0))
        
        # Adicionar gráfico opcional se houver dados suficientes
        if st.session_state.threat_stats["high"] > 0 or st.session_state.threat_stats["medium"] > 0 or st.session_state.threat_stats["low"] > 0:
            data = {
                "Tipo": ["Alto", "Médio", "Baixo"],
                "Quantidade": [
                    st.session_state.threat_stats["high"],
                    st.session_state.threat_stats["medium"],
                    st.session_state.threat_stats["low"]
                ]
            }
            df = pd.DataFrame(data)
            fig = px.pie(df, values="Quantidade", names="Tipo", title="Distribuição de Ameaças")
            st.plotly_chart(fig, use_container_width=True)
    
    def _render_controls(self):
        """Renderiza controles simplificados"""
        with st.container():
            st.subheader("📊 Monitoramento de Rede")
            
            # Status de monitoramento automático
            st.success("✅ Sistema de Monitoramento Ativo")
            
            # Seção para verificar bloqueio real
            st.subheader("🔍 Verificação de Bloqueio Real")
            with st.expander("Verificar se um IP está bloqueado no firewall"):
                if "blocked_ips" in st.session_state and len(st.session_state.blocked_ips) > 0:
                    st.write("#### IPs atualmente bloqueados no sistema:")
                    blocked_list = list(st.session_state.blocked_ips)
                    
                    for ip in blocked_list:
                        col1, col2 = st.columns([4, 1])
                        with col1:
                            st.write(f"🛑 **{ip}**")
                        with col2:
                            if st.button(f"Verificar", key=f"check_{ip}"):
                                is_blocked = self._check_ip_blocked(ip)
                                if is_blocked:
                                    st.success(f"✅ O IP {ip} está realmente bloqueado no firewall")
                                else:
                                    st.error(f"❌ O IP {ip} NÃO está bloqueado no firewall")
                else:
                    st.info("Nenhum IP foi bloqueado ainda.")
                    
                st.write("---")
                st.write("Teste o bloqueio tentando pingar o IP:")
                st.code("ping 192.168.1.100")
                st.write("Se o IP estiver bloqueado, você verá erros de timeout ou falha na conexão.")
    
    def _check_ip_blocked(self, ip):
        """Verifica se um IP está realmente bloqueado no firewall
        
        Args:
            ip (str): O IP a verificar
            
        Returns:
            bool: True se estiver bloqueado, False caso contrário
        """
        try:
            system = platform.system().lower()
            
            if system == "windows":
                rule_name = f"BlockIP-{ip.replace('.', '-')}"
                check_command = f'netsh advfirewall firewall show rule name="{rule_name}"'
                result = subprocess.run(check_command, shell=True, capture_output=True, text=True)
                
                return "No rules match the specified criteria" not in result.stdout
                
            elif system == "linux":
                check_command = f"sudo iptables -C INPUT -s {ip} -j DROP"
                result = subprocess.run(check_command, shell=True, capture_output=True)
                
                return result.returncode == 0
                
            else:
                return False
                
        except Exception as e:
            self.logger.log_activity(f"Erro ao verificar bloqueio do IP {ip}: {str(e)}", 'error')
            return False
    
    def _simulate_random_attack(self):
        """Simula um ataque com nível de risco variado com chances iguais"""
        # Decidir o nível de risco (33% para cada)
        risk_chance = random.random()
        
        # Lista de IPs por categoria de risco
        high_risk_ips = [
            "192.168.1." + str(random.randint(1, 254)),
            "10.0.0." + str(random.randint(1, 254)),
            "172.16.0." + str(random.randint(1, 254)),
            "45.33." + str(random.randint(1, 254)) + "." + str(random.randint(1, 254)),
            "104.131." + str(random.randint(1, 254)) + "." + str(random.randint(1, 254)),
            "185.25." + str(random.randint(1, 254)) + "." + str(random.randint(1, 254))
        ]
        
        medium_risk_ips = [
            "8.8.8." + str(random.randint(1, 254)),
            "1.1.1." + str(random.randint(1, 254)),
            "208.67.222." + str(random.randint(1, 254)),
            "195.12." + str(random.randint(1, 254)) + "." + str(random.randint(1, 254))
        ]
        
        low_risk_ips = [
            "216.58.215." + str(random.randint(1, 254)),
            "151.101." + str(random.randint(1, 254)) + "." + str(random.randint(1, 254)),
            "13.32." + str(random.randint(1, 254)) + "." + str(random.randint(1, 254))
        ]
        
        # Selecionar nível de risco e IP correspondente (33% cada)
        if risk_chance < 0.33:  # 33% chance alta
            risk_level = "high"
            selected_ip = random.choice(high_risk_ips)
            risk_text = "ALTO"
            log_type = 'error'
            threat_types = [
                "Tentativa de Acesso Não Autorizado",
                "Injeção de SQL",
                "Execução de Código Remoto",
                "Ataque de Força Bruta",
                "Propagação de Malware",
                "Comunicação com Servidor C&C",
                "Varredura de Vulnerabilidades"
            ]
            threat_details = [
                "Padrão de ataque conhecido detectado",
                "Múltiplas tentativas de autenticação falhas",
                "Tráfego malicioso detectado",
                "Assinatura de exploit conhecida",
                "Comportamento consistente com roubo de dados"
            ]
        elif risk_chance < 0.66:  # 33% chance média
            risk_level = "medium"
            selected_ip = random.choice(medium_risk_ips)
            risk_text = "MÉDIO"
            log_type = 'warning'
            threat_types = [
                "Atividade de Rede Suspeita",
                "Comportamento Anômalo de Usuário",
                "Transferência Incomum de Dados",
                "Conexão Suspeita",
                "Tentativa de Acesso a Recurso Restrito"
            ]
            threat_details = [
                "Padrão de tráfego incomum",
                "Comunicação com domínio recentemente registrado",
                "Tráfego suspeito detectado",
                "Volume de dados anormal"
            ]
        else:  # 33% chance baixa
            risk_level = "low"
            selected_ip = random.choice(low_risk_ips)
            risk_text = "BAIXO"
            log_type = 'info'
            threat_types = [
                "Atividade Incomum",
                "Tentativa de Login de Nova Localização",
                "Acesso a Recursos Sensíveis",
                "Comportamento Fora de Padrão",
                "Alteração de Configuração"
            ]
            threat_details = [
                "Possível falso positivo",
                "Comportamento incomum detectado",
                "Pequeno desvio de comportamento padrão"
            ]
        
        # Seleciona protocolos e portas
        protocol = random.choice(["TCP", "UDP", "HTTP", "HTTPS", "DNS", "SMB", "RDP", "SSH"])
        port = random.randint(1, 65535)
        
        # Registra o alerta
        log_message = f"⚠️ ATAQUE SIMULADO: {random.choice(threat_types)} de {selected_ip}:{port} via {protocol} - Risco {risk_text}"
        self.logger.log_activity(log_message, log_type)
        
        # Envia para análise no security agent
        threat_data = {
            "ip": selected_ip,
            "type": random.choice(threat_types),
            "details": random.choice(threat_details),
            "timestamp": datetime.now().isoformat(),
            "risk_level": risk_level
        }
        
        # Analisar a ameaça
        self.security_agent.analyze_threat(threat_data)
    
    def _render_mcp(self):
        """Renderiza o componente de Protocolo de Contexto do Modelo"""
        st.subheader("🧠 Model Context Protocol (MCP)")
        
        # Atualizar o contexto do MCP a cada 15 segundos
        current_time = time.time()
        if "last_mcp_update" not in st.session_state:
            st.session_state.last_mcp_update = 0
            
        if current_time - st.session_state.last_mcp_update >= 15:
            self._update_model_context()
            # Realizar correlação automática com o contexto
            self._correlate_events(automatic=True)
            st.session_state.last_mcp_update = current_time
        
        # Exibir o contexto em colunas
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Estado Atual do Sistema**")
            st.info(st.session_state.mcp_context["contexto_ameaças"])
            
            # Status do sistema em métricas
            col_a, col_b = st.columns(2)
            with col_a:
                st.metric("Nível de Confiança", f"{st.session_state.mcp_context['nível_confiança']}%")
            with col_b:
                st.metric("Análises Pendentes", st.session_state.mcp_context["análises_pendentes"])
                
            # Adicionar novo: Métricas de auto-otimização
            if "feedback_recebido" in st.session_state.mcp_context:
                st.metric("Feedback Recebido", st.session_state.mcp_context["feedback_recebido"], delta=1)
                
            st.caption(f"Última atualização: {st.session_state.mcp_context['última_atualização']}")
            # Exibir informação sobre correlação automática
            st.success("✅ Correlação automática ativa")
            if "last_correlation_time" in st.session_state:
                tempo_desde_correlacao = time.time() - st.session_state.last_correlation_time
                st.caption(f"Próxima correlação em ~{15 - int(tempo_desde_correlacao % 15)} segundos")
                
        with col2:
            st.markdown("**Padrões Identificados**")
            
            if st.session_state.mcp_context["padrões_identificados"]:
                for pattern in st.session_state.mcp_context["padrões_identificados"]:
                    st.info(pattern)
            else:
                st.info("Nenhum padrão identificado ainda. O sistema está coletando dados.")
                
            if st.session_state.mcp_context["eventos_correlacionados"]:
                st.markdown("**Eventos Correlacionados**")
                for event in st.session_state.mcp_context["eventos_correlacionados"]:
                    st.warning(event)
        
        # Exibir linha do tempo de aprendizado (novo)
        if "threat_analysis_history" in st.session_state and len(st.session_state.threat_analysis_history) > 0:
            with st.expander("📈 Evolução do Aprendizado do Sistema", expanded=False):
                st.write("### Histórico de Análises e Aprendizado")
                
                # Preparar dados para visualização
                history_data = []
                for entry in st.session_state.threat_analysis_history[-20:]:  # Mostrar apenas as 20 últimas entradas
                    history_data.append({
                        "Timestamp": pd.to_datetime(entry["timestamp"]).strftime("%H:%M:%S"),
                        "IP": entry["ip"],
                        "Nível": entry["risk_level"],
                        "Score": entry["score"],
                        "Confiança": entry["confidence"]
                    })
                
                if history_data:
                    history_df = pd.DataFrame(history_data)
                    
                    # Gráfico de evolução da confiança
                    confidence_fig = px.line(
                        history_df, 
                        x=history_df.index, 
                        y="Confiança",
                        title="Evolução da Confiança nas Análises",
                        labels={"x": "Análise", "Confiança": "Nível de Confiança"}
                    )
                    confidence_fig.update_layout(yaxis_range=[0, 1])
                    st.plotly_chart(confidence_fig, use_container_width=True)
                    
                    # Tabela com histórico
                    st.dataframe(history_df, use_container_width=True)
    
    def _update_model_context(self):
        """Atualiza o contexto do modelo MCP"""
        # Atualizar informações do contexto
        contextos = [
            "Analisando padrões de tráfego suspeitos", 
            "Correlacionando eventos de segurança", 
            "Avaliando comportamentos anômalos", 
            "Processando IOCs recentes",
            "Monitorando atividades de rede"
        ]
        
        confiança = random.randint(70, 99)
        análises = random.randint(0, 5)
        
        st.session_state.mcp_context = {
            "contexto_ameaças": random.choice(contextos),
            "última_atualização": datetime.now().strftime("%H:%M:%S"),
            "nível_confiança": confiança,
            "estado_análise": "Ativo" if confiança > 85 else "Alerta",
            "análises_pendentes": análises,
            "eventos_correlacionados": st.session_state.mcp_context.get("eventos_correlacionados", []),
            "padrões_identificados": st.session_state.mcp_context.get("padrões_identificados", [])
        }
        
        # Registrar no log
        self.logger.log_activity(f"MCP: Contexto atualizado - Confiança: {confiança}%", "info")
    
    def _correlate_events(self, automatic=False, force=False):
        """Correlaciona eventos de segurança para o MCP
        
        Args:
            automatic (bool): Se a correlação foi acionada automaticamente
            force (bool): Se é uma correlação forçada (ignora o tempo mínimo)
        """
        # Verificar se já houve correlação recente (menos de 10 segundos atrás)
        if not force and "last_correlation_time" in st.session_state:
            if time.time() - st.session_state.last_correlation_time < 10:
                return  # Evitar correlações muito frequentes
        
        # Simular correlação de eventos
        eventos = [
            "Múltiplas tentativas de login malsucedidas de IPs similares",
            "Padrão de varredura de portas seguido por tentativas de exploração",
            "Comportamento anômalo em hosts previamente comprometidos",
            "Tráfego de rede suspeito para domínios recém-registrados",
            "Sequência de ações administrativas fora do horário normal",
            "Transferência incomum de dados para destinos externos"
        ]
        
        # Adicionar eventos correlacionados
        correlações = []
        for _ in range(random.randint(1, 3)):
            correlações.append(random.choice(eventos))
            
        st.session_state.mcp_context["eventos_correlacionados"] = correlações
        
        # Identificar padrões com base nas correlações
        padrões = [
            "Possível campanha de ransomware em andamento",
            "Indicadores de APT (Ameaça Persistente Avançada)",
            "Atividade consistente com reconhecimento de rede",
            "Potencial vazamento de dados em progresso",
            "Tentativa de elevação de privilégios detectada"
        ]
        
        # Adicionar 1-2 padrões aleatórios
        st.session_state.mcp_context["padrões_identificados"] = random.sample(padrões, random.randint(1, 2))
        
        # Aumentar confiança após correlação
        st.session_state.mcp_context["nível_confiança"] = min(99, st.session_state.mcp_context["nível_confiança"] + random.randint(1, 5))
        st.session_state.mcp_context["última_atualização"] = datetime.now().strftime("%H:%M:%S")
        
        # Registrar no log
        mode_text = "automática" if automatic else "manual"
        self.logger.log_activity(f"MCP: Correlação {mode_text} - {len(correlações)} eventos correlacionados. {len(st.session_state.mcp_context['padrões_identificados'])} padrões identificados.", "info")
    
    def _render_logs(self):
        """Renderiza seção de logs"""
        st.subheader("📝 Logs em Tempo Real")
        log_container = st.empty()
        
        # Mostrar logs recentes
        logs = self.logger.get_recent_logs(30)
        log_text = "\n".join([f"{log['timestamp']} - {log['message']}" for log in logs])
        log_container.text_area("Últimos 30 logs", log_text, height=400)
    
    def _render_sidebar(self):
        """Renderiza a barra lateral com informações essenciais"""
        st.sidebar.title("Sistema Autônomo Ativo")
        
        # Status do sistema
        if st.session_state.get('monitoring_active', False):
            st.sidebar.success("Sistema de Monitoramento Ativo")
        else:
            st.sidebar.warning("Sistema de Monitoramento Inativo")
        
        # Status da simulação
        if st.session_state.get('simulation_active', False):
            st.sidebar.success("Simulação de Ataques Ativa")
        else:
            st.sidebar.warning("Simulação de Ataques Inativa")
        
        # MCP - Model Context Protocol
        st.sidebar.subheader("🧠 Model Context Protocol")
        with st.sidebar.expander("Detalhes do MCP"):
            st.write("**Eventos Correlacionados**")
            if "eventos_correlacionados" in st.session_state.mcp_context and st.session_state.mcp_context["eventos_correlacionados"]:
                for evento in st.session_state.mcp_context["eventos_correlacionados"]:
                    st.write(f"- {evento}")
            else:
                st.write("Nenhum evento correlacionado ainda.")
        
        # Lista de IPs Monitorados
        if st.session_state.get('monitored_ips'):
            st.sidebar.subheader("IPs Monitorados")
            for ip in st.session_state.monitored_ips:
                st.sidebar.text(f"• {ip}")
        
        # Lista de IPs em Honeypot
        if st.session_state.get('honeypot_ips'):
            st.sidebar.subheader("IPs em Honeypot 🍯")
            for ip in st.session_state.honeypot_ips:
                st.sidebar.text(f"• {ip}")
        
        # Lista de IPs Bloqueados
        if st.session_state.get('blocked_ips'):
            st.sidebar.subheader("IPs Bloqueados")
            for ip in st.session_state.blocked_ips:
                st.sidebar.text(f"• {ip}")
    
    def _render_threat_intelligence(self):
        """Renderiza seção de inteligência de ameaças"""
        st.subheader("🔍 Inteligência de Ameaças")
        
        # Campo de busca de IP
        ip_to_check = st.text_input("Buscar informações de IP")
        if ip_to_check and st.button("Pesquisar"):
            self._display_threat_intelligence(ip_to_check)
    
    def _display_threat_intelligence(self, ip):
        """Exibe informações de inteligência de ameaças na interface"""
        st.info("⏳ Analisando IP... O agente está pensando.")
        
        # Verificar se o sistema está usando LLM ou regras offline
        is_using_llm = not self.threat_intel.offline_mode and self.threat_intel.llm is not None
        
        # Obter dados das "APIs" (simuladas ou reais)
        vt_data = self.threat_intel.check_virustotal(ip)
        abuse_data = self.threat_intel.check_abuseipdb(ip)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**VirusTotal**")
            if "error" not in vt_data:
                st.metric("Detecções Maliciosas", vt_data["malicious"])
                st.metric("Detecções Suspeitas", vt_data["suspicious"])
                st.metric("Detecções Inofensivas", vt_data["harmless"])
            else:
                st.error(vt_data["error"])
        
        with col2:
            st.write("**AbuseIPDB**")
            if "error" not in abuse_data:
                st.metric("Score de Confiança", f"{abuse_data['abuse_confidence_score']}%")
                st.metric("Total de Relatórios", abuse_data["total_reports"])
                if abuse_data["last_reported_at"]:
                    st.write(f"Último relatório: {abuse_data['last_reported_at']}")
            else:
                st.error(abuse_data["error"])
        
        # Análise de ameaça
        if "error" not in vt_data and "error" not in abuse_data:
            threat_intel = self.threat_intel.analyze_threat_intelligence(ip)
            
            # Mostrar emblema LLM se estiver usando modelo
            risk_level_text = threat_intel['level']
            confidence = threat_intel.get('confidence', 0) * 100
            
            if is_using_llm:
                st.subheader(f"Análise de Ameaça: {risk_level_text} 🤖")
                st.info("Análise aprimorada por IA usando modelo de linguagem")
            else:
                st.subheader(f"Análise de Ameaça: {risk_level_text}")
            
            # Barra de progresso com cor baseada no risco
            risk_color = "red" if risk_level_text == "ALTO" else "orange" if risk_level_text == "MÉDIO" else "green"
            st.markdown(
                f"""
                <div style="background-color: #1E1E1E; border-radius: 10px; padding: 10px;">
                    <div style="background-color: {risk_color}; width: {min(threat_intel['score'] * 10, 100)}%; 
                    height: 20px; border-radius: 5px;"></div>
                </div>
                """, 
                unsafe_allow_html=True
            )
            
            # Exibir nível de confiança
            st.metric("Confiança na Análise", f"{confidence:.1f}%")
            
            if threat_intel["details"]:
                st.write("**Detalhes:**")
                for detail in threat_intel["details"]:
                    st.write(f"- {detail}")
            
            # Seção de Explicabilidade - Novo
            if "decision_trace" in threat_intel and threat_intel["decision_trace"]:
                with st.expander("📊 Explicabilidade da Decisão", expanded=False):
                    st.write("### Rastreamento do Processo Decisório")
                    st.info("Veja abaixo cada etapa do processo de tomada de decisão pelo agente autônomo.")
                    
                    # Criar um dataframe para visualização mais clara
                    decision_data = []
                    for i, decision in enumerate(threat_intel["decision_trace"]):
                        decision_data.append({
                            "Etapa": i+1,
                            "Componente": decision["node"],
                            "Decisão": decision["decision"],
                            "Motivo": decision["reason"],
                            "Confiança": f"{decision['confidence']*100:.1f}%"
                        })
                    
                    if decision_data:
                        df = pd.DataFrame(decision_data)
                        st.dataframe(df, use_container_width=True)
                        
                        # Visualização gráfica da confiança por etapa
                        confidence_fig = px.line(
                            df, 
                            x="Etapa", 
                            y=[float(c.strip('%'))/100 for c in df["Confiança"]], 
                            title="Evolução da Confiança no Processo Decisório",
                            labels={"y": "Confiança", "x": "Etapa do Processo"}
                        )
                        confidence_fig.update_layout(yaxis_range=[0, 1])
                        st.plotly_chart(confidence_fig, use_container_width=True)
            
            # Sistema de Feedback - Novo
            with st.expander("🔄 Fornecer Feedback para Aprendizado", expanded=False):
                st.write("### Ajude a melhorar o sistema")
                st.info("Seu feedback será usado para otimizar análises futuras de IPs similares.")
                
                col1, col2 = st.columns(2)
                with col1:
                    is_accurate = st.radio(
                        "A análise está correta?",
                        options=["Sim", "Não"],
                        index=0
                    )
                
                with col2:
                    correct_level = st.selectbox(
                        "Nível de risco correto:",
                        options=["ALTO", "MÉDIO", "BAIXO"],
                        index=["ALTO", "MÉDIO", "BAIXO"].index(risk_level_text)
                    )
                
                feedback_comments = st.text_area(
                    "Comentários adicionais:",
                    placeholder="Explique por que você considera esta classificação correta/incorreta..."
                )
                
                if st.button("Enviar Feedback", type="primary"):
                    was_accurate = is_accurate == "Sim"
                    self.threat_intel.provide_feedback(
                        ip=ip,
                        was_accurate=was_accurate,
                        correct_level=correct_level if not was_accurate else None,
                        comments=feedback_comments
                    )
                    st.success("✅ Feedback registrado com sucesso! O sistema usará estas informações para melhorar análises futuras.")
                    
                    # Atualizar o contexto do MCP com o feedback
                    if "mcp_context" in st.session_state:
                        # Adicionar ao contexto
                        if "feedback_recebido" not in st.session_state.mcp_context:
                            st.session_state.mcp_context["feedback_recebido"] = 0
                        st.session_state.mcp_context["feedback_recebido"] += 1
                        
                        # Registrar padrão aprendido
                        ip_pattern = ".".join(ip.split(".")[:2]) + ".*"
                        if was_accurate:
                            feedback_msg = f"Confirmado que IPs do padrão {ip_pattern} representam risco {risk_level_text}"
                        else:
                            feedback_msg = f"Corrigido: IPs do padrão {ip_pattern} devem ser classificados como {correct_level} (era {risk_level_text})"
                        
                        if "padrões_identificados" in st.session_state.mcp_context:
                            st.session_state.mcp_context["padrões_identificados"].append(feedback_msg)
                        
                        # Aumentar confiança do MCP
                        if "nível_confiança" in st.session_state.mcp_context:
                            # Aumenta mais se o feedback confirmar a decisão original
                            st.session_state.mcp_context["nível_confiança"] += 3 if was_accurate else 1
                            # Limitar a 99
                            st.session_state.mcp_context["nível_confiança"] = min(99, st.session_state.mcp_context["nível_confiança"])
            
            # Botão para bloquear IP
            if st.button(f"Bloquear IP {ip}"):
                result = self.security_agent.block_ip(ip)
                st.write(f"IP {ip} {result}") 