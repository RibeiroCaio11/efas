import json
import requests
from typing import Dict, List, Annotated, TypedDict, Literal, Optional
import time
import streamlit as st
from datetime import datetime
from langgraph.graph import StateGraph
from langchain_openai import OpenAI
from langchain.prompts import PromptTemplate

# Nova classe para representar o estado do grafo
class ThreatState(TypedDict):
    ip: str
    type: str
    details: str
    vt_data: Dict
    abuse_data: Dict
    risk_level: str
    analysis_complete: bool
    score: float
    analysis_details: List[str]
    # Campos para explicabilidade
    decision_trace: List[Dict]
    # Campos para auto-otimização
    feedback: Optional[str]
    was_accurate: Optional[bool]
    confidence: float

class ThreatIntelligence:
    """Classe para análise de inteligência de ameaças usando LangGraph"""
    
    def __init__(self, config):
        self.config = config
        self.llm = self._initialize_llm()
        self.prompt = self._create_prompt()
        # Definindo como False para usar o LLM real agora que temos uma chave API válida
        self.offline_mode = False  
        
        # Acesso às variáveis de sessão do Streamlit
        self.session_state = st.session_state
        
        # Inicializar o histórico de análises para aprendizado
        if 'threat_analysis_history' not in st.session_state:
            st.session_state.threat_analysis_history = []
            
        # Inicializar feedback para auto-otimização
        if 'analysis_feedback' not in st.session_state:
            st.session_state.analysis_feedback = {}
        
        # Inicializar o grafo de análise de ameaças
        self.threat_analysis_graph = self._build_threat_analysis_graph()
    
    def _initialize_llm(self):
        """Inicializa o modelo de linguagem para análise de ameaças"""
        try:
            return OpenAI(
                model="gpt-3.5-turbo-instruct",  # Modelo mais acessível e rápido
                temperature=0.1,
                max_tokens=512,
                api_key=self.config.openai_api_key
            )
        except Exception as e:
            print(f"Erro ao inicializar LLM: {str(e)}")
            return None
    
    def _create_prompt(self):
        """Cria o template de prompt para análise de ameaças"""
        return PromptTemplate(
            input_variables=["ip", "type", "details"],
            template="""
            Você é um especialista em segurança cibernética analisando uma possível ameaça.
            
            Analise os seguintes dados de segurança:
            IP: {ip}
            Tipo de Evento: {type}
            Detalhes: {details}
            
            Determine o nível de ameaça como ALTO, MÉDIO ou BAIXO com base nos padrões a seguir:
            
            - ALTO: IPs envolvidos em ataques de força bruta, execução remota de código, propagação de malware, comunicação com C&C, ou qualquer IP dos padrões 192.168.1.*, 10.0.0.*, 172.16.0.*, 45.33.*, 104.131.*, 185.25.*, 159.65.*
            
            - MÉDIO: IPs envolvidos em atividade suspeita, comportamento anômalo, transferência incomum de dados, ou qualquer IP dos padrões 8.8.8.*, 1.1.1.*, 208.67.222.*, 195.12.*
            
            - BAIXO: IPs com atividade incomum mas provavelmente benigna, possíveis falsos positivos.
            
            Responda apenas com uma única palavra: ALTO, MÉDIO ou BAIXO.
            """
        )
    
    def _build_threat_analysis_graph(self):
        """Constrói o grafo de análise de ameaças usando LangGraph"""
        # Criar o grafo com o estado tipado
        builder = StateGraph(ThreatState)
        
        # Adicionar nós ao grafo
        builder.add_node("check_rules", self._check_rules)
        builder.add_node("fetch_threat_intel", self._fetch_threat_intel)
        builder.add_node("analyze_with_llm", self._analyze_with_llm)
        builder.add_node("calculate_risk_score", self._calculate_risk_score)
        builder.add_node("adjust_with_feedback", self._adjust_with_feedback)
        builder.add_node("finalize_analysis", self._finalize_analysis)
        
        # Definir o ponto de entrada 
        builder.set_entry_point("check_rules")
        
        # Definir o fluxo entre os nós
        builder.add_edge("check_rules", "fetch_threat_intel")
        builder.add_edge("fetch_threat_intel", "analyze_with_llm")
        builder.add_edge("analyze_with_llm", "calculate_risk_score")
        builder.add_edge("calculate_risk_score", "adjust_with_feedback")
        builder.add_edge("adjust_with_feedback", "finalize_analysis")
        
        # Adicionar condicionais para pular a análise de LLM se já houver decisão das regras
        builder.add_conditional_edges(
            "check_rules",
            lambda state: "calculate_risk_score" if state["risk_level"] else "fetch_threat_intel"
        )
        
        # Compilar o grafo
        return builder.compile()
    
    def _log_decision(self, state: ThreatState, node_name: str, decision: str, reason: str, confidence: float = 1.0) -> ThreatState:
        """Adiciona um log de decisão ao rastreamento"""
        if "decision_trace" not in state:
            state["decision_trace"] = []
            
        state["decision_trace"].append({
            "timestamp": datetime.now().isoformat(),
            "node": node_name,
            "decision": decision,
            "reason": reason,
            "confidence": confidence
        })
        
        return state
    
    def _check_rules(self, state: ThreatState) -> ThreatState:
        """Verifica regras predefinidas para determinar nível de risco"""
        ip = state["ip"]
        
        # Inicializar o rastreamento de decisões se necessário
        if "decision_trace" not in state:
            state["decision_trace"] = []
        
        # Inicializar valor de confiança
        state["confidence"] = 0.0
        
        # Verificar primeiro as regras hardcoded de alto risco
        if any(ip.startswith(prefix) for prefix in ["192.168.1.", "10.0.0.", "172.16.0.", "45.33.", "104.131.", "185.25.", "159.65."]):
            state["risk_level"] = "ALTO"
            state["analysis_details"].append("IP pertence a um padrão de alto risco conhecido")
            state["score"] = 8.0
            state["confidence"] = 0.9
            state = self._log_decision(
                state, 
                "check_rules", 
                "Risco ALTO", 
                f"O IP {ip} corresponde a um padrão de alto risco conhecido",
                0.9
            )
        # Verificar regras hardcoded de médio risco
        elif any(ip.startswith(prefix) for prefix in ["8.8.8.", "1.1.1.", "208.67.222.", "195.12."]):
            state["risk_level"] = "MÉDIO"
            state["analysis_details"].append("IP pertence a um padrão de risco médio conhecido")
            state["score"] = 4.0
            state["confidence"] = 0.85
            state = self._log_decision(
                state, 
                "check_rules", 
                "Risco MÉDIO", 
                f"O IP {ip} corresponde a um padrão de risco médio conhecido",
                0.85
            )
        else:
            # Sem regra predefinida, continuar fluxo
            state["risk_level"] = ""
            state = self._log_decision(
                state, 
                "check_rules", 
                "Nenhuma regra aplicável", 
                f"O IP {ip} não corresponde a nenhum padrão de risco conhecido",
                0.5
            )
        
        return state
    
    def _fetch_threat_intel(self, state: ThreatState) -> ThreatState:
        """Busca inteligência de ameaças de fontes externas"""
        ip = state["ip"]
        # Obter dados de inteligência de ameaças
        vt_data = self.check_virustotal(ip)
        abuse_data = self.check_abuseipdb(ip)
        
        state["vt_data"] = vt_data
        state["abuse_data"] = abuse_data
        
        # Registrar a decisão
        vt_status = "com detecções" if "error" not in vt_data and (vt_data.get("malicious", 0) > 0 or vt_data.get("suspicious", 0) > 0) else "sem detecções"
        abuse_status = "com relatórios" if "error" not in abuse_data and abuse_data.get("total_reports", 0) > 0 else "sem relatórios"
        
        state = self._log_decision(
            state, 
            "fetch_threat_intel", 
            "Dados coletados com sucesso", 
            f"Consultado VirusTotal ({vt_status}) e AbuseIPDB ({abuse_status})",
            0.75
        )
        
        return state
    
    def _analyze_with_llm(self, state: ThreatState) -> ThreatState:
        """Analisa a ameaça usando o modelo de linguagem"""
        if self.offline_mode or self.llm is None:
            state = self._log_decision(
                state,
                "analyze_with_llm",
                "Análise LLM ignorada",
                "Modo offline ativado ou LLM não disponível",
                0.5
            )
            return state
        
        try:
            chain = self.prompt | self.llm
            response = chain.invoke(state)
            print(f"Resposta do LLM para {state['ip']}: {response}")
            
            confidence = 0.0
            if "ALTO" in response.upper():
                state["risk_level"] = "ALTO"
                state["analysis_details"].append("Análise LLM: Risco alto identificado")
                confidence = 0.87
            elif "MÉDIO" in response.upper():
                state["risk_level"] = "MÉDIO"
                state["analysis_details"].append("Análise LLM: Risco médio identificado")
                confidence = 0.75
            else:
                state["risk_level"] = "BAIXO"
                state["analysis_details"].append("Análise LLM: Risco baixo identificado")
                confidence = 0.65
            
            state = self._log_decision(
                state,
                "analyze_with_llm",
                f"Risco {state['risk_level']}",
                f"Análise do LLM classificou como {state['risk_level']} com base no tipo '{state['type']}' e detalhes",
                confidence
            )
            
            # Atualizar confiança geral do estado
            state["confidence"] = max(state.get("confidence", 0), confidence)
            
        except Exception as e:
            error_msg = f"Erro na análise LLM: {str(e)}"
            print(error_msg)
            state["analysis_details"].append(error_msg)
            
            state = self._log_decision(
                state,
                "analyze_with_llm",
                "Erro na análise",
                error_msg,
                0.3
            )
        
        return state
    
    def _calculate_risk_score(self, state: ThreatState) -> ThreatState:
        """Calcula o score de risco baseado nas análises de inteligência de ameaças"""
        # Se já tem um nível de risco definido, apenas ajusta o score se necessário
        if state["risk_level"] and not state["score"]:
            if state["risk_level"] == "ALTO":
                state["score"] = 8.0
                state["confidence"] = max(state.get("confidence", 0), 0.85)
            elif state["risk_level"] == "MÉDIO":
                state["score"] = 4.0
                state["confidence"] = max(state.get("confidence", 0), 0.75)
            else:
                state["score"] = 1.0
                state["confidence"] = max(state.get("confidence", 0), 0.6)
                
            state = self._log_decision(
                state,
                "calculate_risk_score",
                f"Score {state['score']} atribuído",
                f"Score atribuído com base no nível de risco pré-determinado ({state['risk_level']})",
                state["confidence"]
            )
            return state
        
        threat_score = state.get("score", 0)
        confidence = state.get("confidence", 0.5)
        vt_data = state["vt_data"]
        abuse_data = state["abuse_data"]
        
        evidence_details = []
        
        # Análise VirusTotal
        if "error" not in vt_data:
            if vt_data["malicious"] > 0:
                old_score = threat_score
                threat_score += vt_data["malicious"] * 2
                state["analysis_details"].append(f"VirusTotal: {vt_data['malicious']} detecções maliciosas")
                evidence_details.append(f"+{vt_data['malicious'] * 2} pontos por {vt_data['malicious']} detecções maliciosas")
                confidence = max(confidence, 0.8)
            if vt_data["suspicious"] > 0:
                old_score = threat_score
                threat_score += vt_data["suspicious"]
                state["analysis_details"].append(f"VirusTotal: {vt_data['suspicious']} detecções suspeitas")
                evidence_details.append(f"+{vt_data['suspicious']} pontos por {vt_data['suspicious']} detecções suspeitas")
                confidence = max(confidence, 0.7)
        else:
            state["analysis_details"].append(f"VirusTotal: {vt_data.get('error', 'Erro desconhecido')}")
            evidence_details.append("Erro na consulta ao VirusTotal")
            confidence = max(confidence, 0.4)
        
        # Análise AbuseIPDB
        if "error" not in abuse_data:
            if abuse_data["abuse_confidence_score"] > 50:
                old_score = threat_score
                added_score = abuse_data["abuse_confidence_score"] / 25
                threat_score += added_score
                state["analysis_details"].append(f"AbuseIPDB: Score de confiança {abuse_data['abuse_confidence_score']}%")
                evidence_details.append(f"+{added_score:.1f} pontos por score de confiança {abuse_data['abuse_confidence_score']}%")
                confidence = max(confidence, abuse_data["abuse_confidence_score"] / 100)
            if abuse_data["total_reports"] > 0:
                old_score = threat_score
                threat_score += abuse_data["total_reports"]
                state["analysis_details"].append(f"AbuseIPDB: {abuse_data['total_reports']} relatórios de abuso")
                evidence_details.append(f"+{abuse_data['total_reports']} pontos por {abuse_data['total_reports']} relatórios de abuso")
                confidence = max(confidence, 0.75)
        else:
            state["analysis_details"].append(f"AbuseIPDB: {abuse_data.get('error', 'Erro desconhecido')}")
            evidence_details.append("Erro na consulta ao AbuseIPDB")
            confidence = max(confidence, 0.4)
            
        # Se não temos dados suficientes
        if not state["analysis_details"]:
            if state["ip"].startswith("192.168"):
                threat_score = 8
                state["analysis_details"].append("Detecção de IP interno com comportamento suspeito")
                evidence_details.append("IP interno com comportamento suspeito")
                confidence = 0.7
            else:
                threat_score = 1
                state["analysis_details"].append("Análise limitada - dados insuficientes")
                evidence_details.append("Dados insuficientes para análise completa")
                confidence = 0.5
        
        state["score"] = threat_score
        state["confidence"] = confidence
        
        # Registrar a decisão de cálculo de score
        state = self._log_decision(
            state,
            "calculate_risk_score",
            f"Score {threat_score:.1f}",
            "Pontuação calculada com base nas evidências: " + ", ".join(evidence_details),
            confidence
        )
        
        return state
    
    def _adjust_with_feedback(self, state: ThreatState) -> ThreatState:
        """Ajusta a análise de risco com base no histórico de feedback"""
        ip = state["ip"]
        
        # Verificar se existe feedback prévio para este IP ou padrão de IP
        ip_prefix = '.'.join(ip.split('.')[:3]) + '.'
        feedback_data = None
        
        # Verificar se há feedback para o IP específico
        if ip in st.session_state.analysis_feedback:
            feedback_data = st.session_state.analysis_feedback[ip]
        # Ou verificar se há feedback para o padrão de IP
        else:
            matching_prefixes = [k for k in st.session_state.analysis_feedback.keys() 
                                if k.startswith(ip_prefix) or ip.startswith(k.split('.')[0] + '.')]
            if matching_prefixes:
                # Usar o feedback mais recente
                latest_key = max(matching_prefixes, 
                                key=lambda k: st.session_state.analysis_feedback[k].get("timestamp", 0))
                feedback_data = st.session_state.analysis_feedback[latest_key]
        
        # Se encontrou feedback relevante, ajustar a análise
        if feedback_data:
            original_score = state["score"]
            original_level = state["risk_level"]
            
            # Ajustar score com base no feedback
            if feedback_data.get("adjustment_factor"):
                state["score"] *= feedback_data["adjustment_factor"]
                
            # Aumentar confiança se a classificação anterior estava correta
            if feedback_data.get("was_accurate", False):
                state["confidence"] = min(1.0, state["confidence"] + 0.1)
            else:
                # Reduzir score se classificação anterior estava errada
                if feedback_data.get("correct_level") == "ALTO" and state["risk_level"] != "ALTO":
                    state["score"] += 3.0
                elif feedback_data.get("correct_level") == "MÉDIO" and state["risk_level"] == "BAIXO":
                    state["score"] += 1.5
                elif feedback_data.get("correct_level") == "BAIXO" and state["risk_level"] != "BAIXO":
                    state["score"] -= 2.0
            
            # Determinar o nível de risco atualizado
            if state["score"] >= 5:
                state["risk_level"] = "ALTO"
            elif state["score"] >= 2:
                state["risk_level"] = "MÉDIO"
            else:
                state["risk_level"] = "BAIXO"
            
            # Registrar a decisão de ajuste com feedback
            if original_level != state["risk_level"] or abs(original_score - state["score"]) > 0.5:
                state = self._log_decision(
                    state,
                    "adjust_with_feedback",
                    f"Ajuste com feedback: {original_level}→{state['risk_level']}",
                    f"Score ajustado de {original_score:.1f} para {state['score']:.1f} com base em feedback histórico",
                    state["confidence"]
                )
            else:
                state = self._log_decision(
                    state,
                    "adjust_with_feedback",
                    "Sem ajustes significativos",
                    "Feedback histórico não alterou significativamente a análise",
                    state["confidence"]
                )
        else:
            # Sem feedback histórico
            state = self._log_decision(
                state,
                "adjust_with_feedback",
                "Sem feedback disponível",
                "Nenhum feedback histórico disponível para este padrão de IP",
                state["confidence"]
            )
            
        return state
    
    def _finalize_analysis(self, state: ThreatState) -> ThreatState:
        """Finaliza a análise determinando o nível de risco final"""
        # Se já tem um nível definido, mantém
        if not state["risk_level"]:
            # Determinar nível de ameaça baseado no score
            if state["score"] >= 5:
                state["risk_level"] = "ALTO"
            elif state["score"] >= 2:
                state["risk_level"] = "MÉDIO"
            else:
                state["risk_level"] = "BAIXO"
                
            state = self._log_decision(
                state,
                "finalize_analysis",
                f"Classificação final: {state['risk_level']}",
                f"Nível de risco determinado com base no score final de {state['score']:.1f}",
                state["confidence"]
            )
        else:
            state = self._log_decision(
                state,
                "finalize_analysis",
                f"Classificação final: {state['risk_level']}",
                "Nível de risco mantido conforme determinado em etapas anteriores",
                state["confidence"]
            )
        
        state["analysis_complete"] = True
        
        # Salvar a análise no histórico para aprendizado
        if hasattr(self, 'session_state'):
            # Limitar o tamanho do histórico para evitar crescimento excessivo
            if len(st.session_state.threat_analysis_history) > 100:
                st.session_state.threat_analysis_history.pop(0)
                
            # Salvar análise no histórico
            st.session_state.threat_analysis_history.append({
                "timestamp": datetime.now().isoformat(),
                "ip": state["ip"],
                "risk_level": state["risk_level"],
                "score": state["score"],
                "confidence": state["confidence"],
                "decision_trace": state["decision_trace"]
            })
            
        return state
    
    def analyze_threat(self, threat_data):
        """Interface compatível com a versão anterior, agora usando o grafo LangGraph"""
        # Prepara o estado inicial
        initial_state: ThreatState = {
            "ip": str(threat_data.get("ip", "")),
            "type": threat_data.get("type", "unknown"),
            "details": threat_data.get("details", ""),
            "vt_data": {},
            "abuse_data": {},
            "risk_level": "",
            "analysis_complete": False,
            "score": 0.0,
            "analysis_details": [],
            "decision_trace": [],
            "feedback": None,
            "was_accurate": None,
            "confidence": 0.5
        }
        
        # Executa o grafo de análise
        final_state = self.threat_analysis_graph.invoke(initial_state)
        
        # Retorna apenas o nível de risco para manter compatibilidade
        return final_state["risk_level"]
    
    def provide_feedback(self, ip: str, was_accurate: bool, correct_level: str = None, comments: str = None):
        """Permite fornecer feedback sobre uma análise para melhorar futuras decisões"""
        if not hasattr(self, 'session_state'):
            return False
            
        # Registrar o feedback
        st.session_state.analysis_feedback[ip] = {
            "timestamp": datetime.now().timestamp(),
            "was_accurate": was_accurate,
            "correct_level": correct_level,
            "comments": comments,
            "adjustment_factor": 1.2 if was_accurate else 0.8
        }
        
        return True
    
    def get_decision_trace(self, ip: str) -> List[Dict]:
        """Retorna o rastreamento detalhado de decisão para um IP específico"""
        if not hasattr(self, 'session_state') or not hasattr(st.session_state, 'threat_analysis_history'):
            return []
            
        # Encontrar a análise mais recente para este IP
        matching_analyses = [a for a in st.session_state.threat_analysis_history if a["ip"] == ip]
        if not matching_analyses:
            return []
            
        # Retornar o rastreamento da análise mais recente
        latest_analysis = max(matching_analyses, key=lambda a: a["timestamp"])
        return latest_analysis.get("decision_trace", [])
    
    def check_virustotal(self, ip: str) -> Dict:
        """Consulta o VirusTotal para informações sobre o IP"""
        if self.offline_mode:
            # Simulação no modo offline
            time.sleep(0.5)  # Simular atraso de rede
            if ip.startswith("192.168"):
                return {
                    "malicious": 5,
                    "suspicious": 3,
                    "harmless": 50,
                    "undetected": 10
                }
            else:
                return {
                    "malicious": 0,
                    "suspicious": 1,
                    "harmless": 70,
                    "undetected": 15
                }
        
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {
                "accept": "application/json",
                "x-apikey": self.config.vt_api_key
            }
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    "malicious": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("suspicious", 0),
                    "harmless": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("harmless", 0),
                    "undetected": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("undetected", 0)
                }
            return {"error": f"Erro na consulta VirusTotal: {response.status_code}"}
        except Exception as e:
            return {"error": f"Erro ao consultar VirusTotal: {str(e)}"}

    def check_abuseipdb(self, ip: str) -> Dict:
        """Consulta o AbuseIPDB para informações sobre o IP"""
        if self.offline_mode:
            # Simulação no modo offline
            time.sleep(0.5)  # Simular atraso de rede
            if ip.startswith("192.168"):
                return {
                    "abuse_confidence_score": 85,
                    "total_reports": 7,
                    "last_reported_at": "2023-12-15T10:25:00+00:00"
                }
            else:
                return {
                    "abuse_confidence_score": 0,
                    "total_reports": 0,
                    "last_reported_at": None
                }
                
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Accept": "application/json",
                "Key": self.config.abuse_ipdb_key
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90
            }
            response = requests.get(url, headers=headers, params=params, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    "abuse_confidence_score": data.get("data", {}).get("abuseConfidenceScore", 0),
                    "total_reports": data.get("data", {}).get("totalReports", 0),
                    "last_reported_at": data.get("data", {}).get("lastReportedAt", None)
                }
            return {"error": f"Erro na consulta AbuseIPDB: {response.status_code}"}
        except Exception as e:
            return {"error": f"Erro ao consultar AbuseIPDB: {str(e)}"}
    
    def analyze_threat_intelligence(self, ip: str) -> Dict:
        """Analisa ameaças usando o grafo de análise LangGraph"""
        # Verificar se o IP já está bloqueado (alto risco)
        if hasattr(self, 'session_state') and ip in self.session_state.get("blocked_ips", set()):
            return {
                "level": "ALTO",
                "score": 9,
                "details": ["IP bloqueado pelo sistema de segurança"],
                "decision_trace": [
                    {
                        "timestamp": datetime.now().isoformat(),
                        "node": "system_check",
                        "decision": "Risco ALTO",
                        "reason": "IP já está na lista de bloqueio do sistema",
                        "confidence": 0.99
                    }
                ]
            }
            
        # Verificar se o IP está em monitoramento (médio risco)
        if hasattr(self, 'session_state') and ip in self.session_state.get("monitored_ips", set()):
            return {
                "level": "MÉDIO",
                "score": 5,
                "details": ["IP em monitoramento pelo sistema de segurança"],
                "decision_trace": [
                    {
                        "timestamp": datetime.now().isoformat(),
                        "node": "system_check",
                        "decision": "Risco MÉDIO",
                        "reason": "IP está na lista de monitoramento do sistema",
                        "confidence": 0.85
                    }
                ]
            }
        
        # Preparar estado inicial
        initial_state: ThreatState = {
            "ip": ip,
            "type": "análise manual",
            "details": "Verificação de inteligência de ameaças solicitada via interface",
            "vt_data": {},
            "abuse_data": {},
            "risk_level": "",
            "analysis_complete": False,
            "score": 0.0,
            "analysis_details": [],
            "decision_trace": [],
            "feedback": None,
            "was_accurate": None,
            "confidence": 0.5
        }
        
        # Executar o grafo de análise
        final_state = self.threat_analysis_graph.invoke(initial_state)
        
        # Retornar resultados no formato esperado pela interface, incluindo rastreamento
        return {
            "level": final_state["risk_level"],
            "score": final_state["score"],
            "details": final_state["analysis_details"],
            "decision_trace": final_state["decision_trace"],
            "confidence": final_state["confidence"]
        } 