import json
import streamlit as st
from datetime import datetime
import requests

class NotificationSystem:
    """Classe para envio de notificações e alertas de segurança"""
    
    def __init__(self, config):
        self.config = config
        self.offline_mode = False  # Alterado para False para permitir envios reais
        # Inicializar lista de notificações na sessão
        if "notifications" not in st.session_state:
            st.session_state.notifications = []
    
    def send_telegram_alert(self, message):
        """Envia alerta via Telegram"""
        try:
            bot_token = self.config.telegram_bot_token
            chat_id = self.config.telegram_chat_id
            
            if not bot_token or not chat_id:
                print("Configuração do Telegram incompleta")
                return False
            
            # Adicionar log para debug
            print(f"Enviando alerta para Telegram - Bot: {bot_token[:5]}... Chat ID: {chat_id}")
                
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            data = {
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "HTML"
            }
            
            # Timeout mais curto para evitar bloqueios
            response = requests.post(url, data=data, timeout=10)
            
            # Log detalhado da resposta para debug
            print(f"Resposta Telegram: Status {response.status_code} - {response.text[:100]}")
            
            response.raise_for_status()  # Verificar se a resposta foi bem-sucedida
            
            return True
        except requests.exceptions.Timeout:
            print(f"ERRO: Timeout ao conectar com a API do Telegram")
            return False
        except requests.exceptions.RequestException as e:
            print(f"ERRO: Falha na requisição para Telegram: {str(e)}")
            return False
        except Exception as e:
            print(f"ERRO ao enviar alerta para o Telegram: {str(e)}")
            return False
    
    def send_discord_alert(self, message):
        """Envia alerta via webhook do Discord"""
        try:
            webhook_url = self.config.discord_webhook
            
            if not webhook_url:
                print("Webhook do Discord não configurado")
                return False
            
            # Adicionar log para debug
            print(f"Enviando alerta para Discord - Webhook: {webhook_url[:20]}...")
                
            data = {
                "content": message,
                "username": "Agente de Segurança",
                "avatar_url": "https://i.imgur.com/4M34hi2.png"
            }
            
            # Timeout mais curto para evitar bloqueios
            response = requests.post(webhook_url, json=data, timeout=10)
            
            # Log detalhado da resposta para debug
            print(f"Resposta Discord: Status {response.status_code} - {response.text[:100]}")
            
            response.raise_for_status()  # Verificar se a resposta foi bem-sucedida
            
            return True
        except requests.exceptions.Timeout:
            print(f"ERRO: Timeout ao conectar com o webhook do Discord")
            return False
        except requests.exceptions.RequestException as e:
            print(f"ERRO: Falha na requisição para Discord: {str(e)}")
            return False
        except Exception as e:
            print(f"ERRO ao enviar alerta para o Discord: {str(e)}")
            return False
    
    def notify_threat(self, ip, threat_data):
        """Envia notificação de ameaça para canais configurados"""
        # Log para debug
        print(f"========= ENVIANDO NOTIFICAÇÃO DE AMEAÇA =========")
        print(f"IP: {ip}")
        print(f"Nível: {threat_data.get('level', 'Desconhecido')}")
        print(f"Detalhes: {threat_data.get('details', ['Sem detalhes'])}")
        print(f"============================================")
        
        # Criar mensagem formatada para os canais
        message = f"""🚨 ALERTA DE SEGURANÇA 🚨
IP: {ip}
Nível: {threat_data.get('level', 'Desconhecido')}
Detalhes: {', '.join(threat_data.get('details', ['Sem detalhes']))}
Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}"""
        
        # Se estiver em modo offline, apenas simular
        if self.offline_mode:
            print("SIMULAÇÃO: Notificação seria enviada (modo offline)")
            self.send_notification(f"SIMULADO: Alerta de ameaça para IP {ip}", "alta")
            return {"telegram": True, "discord": True, "success": True, "simulated": True}
            
        # Enviar para os canais configurados
        telegram_result = self.send_telegram_alert(message)
        discord_result = self.send_discord_alert(message)
        
        # Log dos resultados para debug
        print(f"Resultado Telegram: {'Sucesso' if telegram_result else 'Falha'}")
        print(f"Resultado Discord: {'Sucesso' if discord_result else 'Falha'}")
        
        # Registrar notificação no sistema local também
        self.send_notification(f"Alerta de ameaça para IP {ip} - Nível {threat_data.get('level', 'Desconhecido')}", 
                              "alta" if threat_data.get('level') == "ALTO" else "média")
        
        return {
            "telegram": telegram_result,
            "discord": discord_result,
            "success": telegram_result or discord_result  # Sucesso se pelo menos um canal funcionou
        }
    
    def send_notification(self, message, priority="normal"):
        """Envia uma notificação com prioridade especificada
        
        Args:
            message (str): Mensagem de notificação
            priority (str): Prioridade da notificação ('alta', 'média', 'normal')
        """
        try:
            # Criação do objeto de notificação
            notification = {
                "message": message,
                "priority": priority,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "read": False
            }
            
            # Adicionar à lista de notificações na sessão
            st.session_state.notifications.append(notification)
            
            # Registrar no console (simulação)
            print(f"NOTIFICAÇÃO [{priority.upper()}]: {message}")
            
            return True
        except Exception as e:
            print(f"Erro ao enviar notificação: {str(e)}")
            return False
            
    def get_notifications(self, limit=10, only_unread=False):
        """Retorna as notificações mais recentes
        
        Args:
            limit (int): Número máximo de notificações a retornar
            only_unread (bool): Se True, retorna apenas notificações não lidas
            
        Returns:
            list: Lista de notificações
        """
        if "notifications" not in st.session_state:
            return []
            
        notifications = st.session_state.notifications
        
        if only_unread:
            notifications = [n for n in notifications if not n["read"]]
            
        # Ordenar por timestamp (mais recentes primeiro) e limitar
        return sorted(notifications, 
                     key=lambda x: x["timestamp"], 
                     reverse=True)[:limit]
    
    def mark_as_read(self, index):
        """Marca uma notificação como lida
        
        Args:
            index (int): Índice da notificação a ser marcada
        """
        if (0 <= index < len(st.session_state.notifications)):
            st.session_state.notifications[index]["read"] = True 