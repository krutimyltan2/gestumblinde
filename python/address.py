"""
Address class.
"""

from enum import Enum
import copy
from utils import toByte, toInt

# unmagic numbers, note that end indices are the
# last entry index + 1
LAYER_ADDRESS_START=0
LAYER_ADDRESS_END=4
TREE_ADDRESS_START=4
TREE_ADDRESS_END=16
TYPE_START=16
TYPE_END=20
HASH_ADDRESS_START=28
HASH_ADDRESS_END=32
ADDRESS_DATA_LEN=32
KEY_PAIR_ADDRESS_START=20
KEY_PAIR_ADDRESS_END=24
CHAIN_ADDRESS_START=24
CHAIN_ADDRESS_END=28
TREE_HEIGHT_START=24
TREE_HEIGHT_END=28
TREE_INDEX_START=28
TREE_INDEX_END=32

class AddressType(Enum):
    """Enum for types of address"""
    WOTS_HASH = 0
    WOTS_PK = 1
    TREE = 2
    FORS_TREE = 3
    FORS_ROOTS = 4
    WOTS_PRF = 5
    FORS_PRF = 6

    def __int__(self):
        return self.value
    
class Address:
    """Stores an SLH-DSA address (same class for all types)"""
    def __init__(self, b=None):
        """Initialize an address"""
        if b == None:
            self.data = bytearray([0]*32)
        else:
            self.data = bytearray(b)

    def copy(self):
        """Make a (deep) copy of an address"""
        cself = copy.deepcopy(self)
        return cself

    def get_layer_address_raw(self) -> bytearray:
        """Get the layer address as raw bytes"""
        return self.data[:4]

    def set_layer_address_raw(self, layer_address: bytes):
        """Set the layer address from raw bytes"""
        assert len(layer_address) == 4
        self.data[LAYER_ADDRESS_START:LAYER_ADDRESS_END] = layer_address

    def get_layer_address(self) -> int:
        """Get the layer address as an integer"""
        return toInt(self.get_layer_address_raw(), 4)

    def set_layer_address(self, layer_address: int):
        """Set the layer address from an integer"""
        assert layer_address < 2**32
        self.set_layer_address_raw(toByte(layer_address, 4))

    def get_tree_address_raw(self) -> bytearray:
        """Get the tree address as raw bytes"""
        return self.data[TREE_ADDRESS_START:TREE_ADDRESS_END]

    def set_tree_address_raw(self, tree_address: bytes):
        """Set the tree address from raw bytes"""
        assert len(tree_address) == 12
        self.data[TREE_ADDRESS_START:TREE_ADDRESS_END] = tree_address

    def get_tree_address(self) -> int:
        """Get the tree address as integer"""
        return toInt(self.get_tree_address_raw(), 12)

    def set_tree_address(self, tree_address: int):
        """Set the tree address from raw bytes"""
        assert tree_address < 2**(8*12)
        self.set_tree_address_raw(toByte(tree_address, 12))

    def get_type(self) -> bytearray:
        """Get type of address"""
        return self.data[TYPE_START:TYPE_END]

    def set_type(self, type_: bytes):
        """Set the type of the address"""
        assert len(type_) == 4
        self.data[TYPE_START:TYPE_END] = type_

    def get_typeaddress(self) -> AddressType:
        """Get the address as a AddressType enum"""
        return AddressType(toInt(self.get_type(), 4))

    def __set_typeaddress(self, new_type: AddressType):
        self.set_type(toByte(int(new_type), 4))

    def get_hash_address(self) -> bytearray:
        """Get the hash address of WOTS_HASH"""
        assert self.get_typeaddress() == AddressType.WOTS_HASH
        return self.data[HASH_ADDRESS_START:HASH_ADDRESS_END]

    def set_hash_address_raw(self, value: bytes):
        """Set the hash address from raw bytes"""
        assert self.get_typeaddress() == AddressType.WOTS_HASH
        assert len(value) == 4
        self.data[HASH_ADDRESS_START:HASH_ADDRESS_END] = value

    def set_hash_address(self, value: int):
        """Set the hash address from an int"""
        assert self.get_typeaddress() == AddressType.WOTS_HASH
        assert value >= 0 # valid uint32
        assert value < 2**32 # valid uint32
        self.set_hash_address_raw(toByte(value, 4))

    def set_type_and_clear(self, new_type: AddressType):
        """Set the stype and clear everything following it in the address"""
        # set new address type:
        self.__set_typeaddress(new_type)
        # clear everything after type:
        self.data[TYPE_END:ADDRESS_DATA_LEN] = b"\x00"*(ADDRESS_DATA_LEN - TYPE_END)

    def has_key_pair_address(self) -> bool:
        """Check if type is one of the types that has a key pair address"""
        return self.get_typeaddress() in \
            [AddressType.WOTS_HASH,
             AddressType.WOTS_PK,
             AddressType.FORS_TREE,
             AddressType.FORS_ROOTS,
             AddressType.WOTS_PRF,
             AddressType.FORS_PRF]

    def get_key_pair_address(self) -> bytearray:
        """Get the key pair address"""
        assert self.has_key_pair_address()
        return self.data[KEY_PAIR_ADDRESS_START:KEY_PAIR_ADDRESS_END]

    def set_key_pair_address(self, new_kpa: bytes):
        """Set the keypair adress to `new_kpa`"""
        assert self.has_key_pair_address()
        assert len(new_kpa) == 4
        self.data[KEY_PAIR_ADDRESS_START:KEY_PAIR_ADDRESS_END] = new_kpa

    def has_chain_address(self) -> bool:
        """Check if type is one of the types that has a chain address"""
        return self.get_typeaddress() in \
            [AddressType.WOTS_HASH,
             AddressType.WOTS_PRF]

    def get_chain_address_raw(self) -> bytearray:
        """Get the chain address as raw bytes"""
        assert self.has_chain_address()
        return self.data[CHAIN_ADDRESS_START:CHAIN_ADDRESS_END]

    def set_chain_address_raw(self, new_ca: bytes):
        """Set the chain address from raw bytes"""
        assert self.has_chain_address()
        assert len(new_ca) == 4
        self.data[CHAIN_ADDRESS_START:CHAIN_ADDRESS_END] = new_ca

    def get_chain_address(self) -> int:
        """Get the chain address as an int"""
        return toInt(self.get_chain_address_raw(), 4)

    def set_chain_address(self, new_ca: int):
        """Set the chain address from an int"""
        assert new_ca < 2**32
        self.set_chain_address_raw(toByte(new_ca, 4))

    def has_tree_height(self) -> bool:
        """Check if type is one of the types that has a tree height"""
        return self.get_typeaddress() in \
            [AddressType.TREE,
             AddressType.FORS_TREE,
             AddressType.FORS_PRF]

    def get_tree_height_raw(self) -> bytearray:
        """Get the tree height as raw bytes"""
        assert self.has_tree_height()
        return self.data[TREE_HEIGHT_START:TREE_HEIGHT_END]

    def get_tree_height(self) -> int:
        """Get the tree height as an integer"""
        return toInt(self.get_tree_height_raw(), 4)

    def set_tree_height_raw(self, new_height: bytes):
        """Set the tree height from raw bytes"""
        assert self.has_tree_height()
        assert len(new_height) == 4
        self.data[TREE_HEIGHT_START:TREE_HEIGHT_END] = new_height

    def set_tree_height(self, new_height: int):
        """Set the tree height from an integer"""
        assert new_height < 2**32
        self.set_tree_height_raw(toByte(new_height, 4))

    def has_tree_index(self):
        """Check if type is one of the types that has a tree index"""
        return self.get_typeaddress() in \
            [AddressType.TREE,
             AddressType.FORS_TREE,
             AddressType.FORS_PRF]

    def get_tree_index_raw(self) -> bytes:
        """Get the tree index as raw bytes"""
        assert self.has_tree_index()
        return self.data[TREE_INDEX_START:TREE_INDEX_END]

    def get_tree_index(self) -> int:
        """Get the tree index as an integer"""
        return toInt(self.get_tree_index_raw(), 4)

    def set_tree_index_raw(self, new_ti: bytes):
        """Set the tree index from raw bytes"""
        assert self.has_tree_index()
        assert len(new_ti) == 4
        self.data[TREE_INDEX_START:TREE_INDEX_END] = new_ti

    def set_tree_index(self, new_ti: int):
        """Set the tree index from an integer"""
        assert new_ti < 2**32
        self.set_tree_index_raw(toByte(new_ti, 4))
