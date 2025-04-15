import os
import streamlit as st

class Config:
    """Classe para gerenciar todas as configurações do sistema"""
    
    def __init__(self):
        # Configurar chaves de API
        self._set_environment_variables()
        self._load_api_keys()
        
    def _set_environment_variables(self):
        """Define as variáveis de ambiente com as chaves de API"""
        os.environ["VT_API_KEY"] = 
        os.environ["ABUSE_IPDB_KEY"] = 
        os.environ["TELEGRAM_BOT_TOKEN"] = 
        os.environ["TELEGRAM_CHAT_ID"] = ""
        os.environ["DISCORD_WEBHOOK"] = ""
        # Usando a chave de API fornecida pelo usuário
        os.environ["OPENAI_API_KEY"] = ""
    
    def _load_api_keys(self):
        """Carrega as chaves de API das variáveis de ambiente"""
        self.vt_api_key = os.getenv("VT_API_KEY")
        self.abuse_ipdb_key = os.getenv("ABUSE_IPDB_KEY")
        self.telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
        self.telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID")
        self.discord_webhook = os.getenv("DISCORD_WEBHOOK")
        self.openai_api_key = os.getenv("OPENAI_API_KEY") 
