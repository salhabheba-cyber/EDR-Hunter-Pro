"""
EDR-Hunter Pro - Telegram Alerts
"""

import requests
from datetime import datetime

class TelegramAlert:
    def __init__(self, bot_token, chat_id):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    
    def send_alert(self, event):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        message = f"""
🚨 EDR-Hunter Pro Alert 🚨

Time: {timestamp}
Severity: {event.get('severity', 'HIGH')}

Details:
• Process Count: {event.get('process_count', 'N/A')}
• Network Connections: {event.get('network_connections', 'N/A')}
• CPU Usage: {event.get('cpu_usage', 'N/A')}%
• Memory Usage: {event.get('memory_usage', 'N/A')} MB

Action: Investigate immediately!
        """
        
        payload = {
            'chat_id': self.chat_id,
            'text': message,
            'parse_mode': 'Markdown'
        }
        
        try:
            response = requests.post(self.api_url, data=payload)
            return response.status_code == 200
        except:
            return False
