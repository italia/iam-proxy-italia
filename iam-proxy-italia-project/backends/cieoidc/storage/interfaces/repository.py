from abc import ABC, abstractmethod
from typing import Generic, TypeVar, Any, List, Optional


T = TypeVar("T")

class IBaseRepository(ABC, Generic[T]):

    @abstractmethod
    def add(self, entity: T) -> Optional[str]:
        """
        Create entity and insert it into the repository.
        :param entity: entity to insert
        :return: id of inserted entity None otherwise. return None if error occurred
        """

    @abstractmethod
    def remove(self, entity_id: str) -> Optional[bool]:
        """
        Delete entity from the repository.
        :param entity_id: id of entity to delete
        :return True if entity was deleted False otherwise. Return None if error occurred
        """

    @abstractmethod
    def update(self, entity_id:str, entity:T, override=False) -> Optional[bool]:
        """
        Update entity on the repository.
        :param entity_id: id of entity to delete
        :param entity: entity to update
        :param override: True if entity should be overridden otherwise only the populated fields will be updated
        :return True if entity was successfully update False otherwise. return None if error occurred
        """

    @abstractmethod
    def find_by_id(self, entity_id: str) -> Optional[T]:
        """
        Find entity by its identifier from the repository.
        :param entity_id: id of entity to find
        :return entity if found None otherwise
        """

    @abstractmethod
    def find_all(self, filters: dict[str, Any]) -> List[T]:
        """
        Find all entity from the repository.
        :param filters: filters to apply to the entity
        :return list of entities matching the filters.
        """
