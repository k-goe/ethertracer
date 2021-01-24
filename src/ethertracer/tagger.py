from ethertracer import opcodes as opc
import numpy as np

def is_mnemonic(byte, mnemonic):
    return opc.BYTECODES[byte].name == mnemonic


def tag_valid_mnemonics(machine_code):
    """
    Tags all indices with valid opcodes and returns them

    :param machine_code: Sequence of hexadecimal numbers
    :return: List of boolean. True if given integer is a valid opcode, False otherwise
    """
    tags = list(machine_code[i] in opc.BYTECODES.keys() for i in range(0, len(machine_code)))

    return np.array(tags)


def tag_invalid_mnemonics(machine_code):
    """
    Tags all indices with invalid opcodes and returns them

    :param machine_code: Sequence of hexadecimal numbers
    :return: List of boolean. True if given integer is a invalid opcode, False otherwise
    """
    tags = list(machine_code[i] not in opc.BYTECODES.keys() for i in range(0, len(machine_code)))

    return np.array(tags)


def tag_mnemonic(machine_code, mnemonic):
    """
    Tags all indices with a specific opcode and returns them

    :param machine_code: Sequence of hexadecimal numbers
    :param mnemonic: String of a mnemonic
    :return: List of booleans where every occurrence of the given mnemonic is marked as True
    """
    tags = list(machine_code[i] == opc.OPCODES[mnemonic].code for i in range(0, len(machine_code)))

    return np.array(tags)


def tag_push_data(machine_code):
    """
    Tags all integers that refers to a push command

    :param machine_code: Sequence of hexadecimal numbers
    :return: List of boolean. True if integer belongs to a push command
    """

    push1 = opc.opcode_by_name("PUSH1").code
    push32 = opc.opcode_by_name("PUSH32").code

    i = 0
    tags = [False] * len(machine_code)  # result storage

    while i < len(machine_code):
        instruction = machine_code[i]

        if (instruction >= push1 and instruction <= push32):  # found push command

            identified_push_number = int(opc.BYTECODES[instruction].code - push1) + 1
            for j in range(i + 1, i + identified_push_number + 1):
                if(j >= len(machine_code)):
                    break
                tags[j] = True

            i = i + identified_push_number

        i = i + 1

    return np.array(tags)





