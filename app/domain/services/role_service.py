from app.domain.entities.roles import Role
from app.ports.outbound.mongo_port import MongoPort

class RoleService:
    def __init__(self, mongo_port: MongoPort):
        self.mongo_port = mongo_port

    def create_role(self, role: Role) -> str:
        role_dict = role.model_dump()
        return self.mongo_port.insert_role(role_dict)
    
    def get_roles(self) -> list[Role]:
        roles_cursor = self.mongo_port.collection.find()
        roles = [Role(**role) for role in roles_cursor]
        return roles
