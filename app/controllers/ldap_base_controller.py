from abc import ABC, abstractmethod

class LDAPBaseController(ABC):
    @abstractmethod
    def connect(self):
        pass

    @abstractmethod
    def disconnect(self):
        pass

    @abstractmethod
    def search(self, base_dn: str, search_filter: str, scope: str, attributes: list):
        pass
    
    @abstractmethod
    def add_entry(self, dn: str, attributes: dict, password: str):
        pass

    @abstractmethod
    def modify_entry(self, dn: str, changes: dict):
        pass

    @abstractmethod
    def delete_entry(self, dn: str):
        pass
    
    @abstractmethod
    def get_entry(self, dn: str):
        pass
    
    @abstractmethod
    def check_connection(self):
        pass
    
    @abstractmethod
    def authenticate(self, user_dn: str, password: str):
        pass