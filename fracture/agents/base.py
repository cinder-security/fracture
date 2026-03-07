from abc import ABC, abstractmethod
from fracture.core.target import AITarget


class BaseAgent(ABC):
    def __init__(self, target: AITarget):
        self.target = target
        self.name = self.__class__.__name__

    @abstractmethod
    async def run(self, **kwargs):
        """Execute the agent and return results."""
        ...

    def __repr__(self):
        return f"{self.name}(target={self.target.name})"
