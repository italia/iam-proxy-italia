from abc import ABC, abstractmethod
from typing import Generic, TypeVar, Any, List, Optional


T = TypeVar("T")

class IBaseRepository(ABC, Generic[T]):

    @abstractmethod
    def add(self, entity: T) -> Optional[str]:
        """
        Create entity and insert it into the repository.
        @params entity: entity to insert
        @returns id of inserted entity None otherwise
        """

    @abstractmethod
    def remove(self, entity_id: str) -> bool:
        """
        Delete entity from the repository.
        @params entity_id: id of entity to delete
        @returns True if entity was deleted False otherwise
        """

    @abstractmethod
    def find_by_id(self, entity_id: str) -> Optional[T]:
        """
        Find entity by its identifier from the repository.
        @params entity_id: id of entity to find
        @returns entity if found None otherwise
        """

    @abstractmethod
    def find_all(self, filters: dict[str, Any]) -> List[T]:
        """
        Find all entity from the repository.
        @params filters: filters to apply to the entity
        @returns list of entities matching the filters
        """
