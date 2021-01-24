from ethertracer import tagger as tag
from ethertracer import helpers as hlp
from ethertracer import opcodes as opc
import numpy as np


def segment_code(machine_code, start_flags_mask, end_flags_mask, masking=None):
    """
    Splits the machine code into segments

    :param machine_code: Sequence of hexadecimal numbers
    :param start_flags_mask: List of booleans. Specifies the starting of a segment
    :param end_flags_mask: List of booleans. Specifies the end of a segment
    :param masking: List of booleans. Indicate parts of the code that should not be taken into account from the algorithm
    :return: A list of integers. The sequence of the same integer defines a segment
    """

    if (masking is not None):
        start_flags_mask = np.logical_and(start_flags_mask, masking)
        end_flags_mask = np.logical_and(end_flags_mask, masking)

    segments = hlp.segment_list(start_flags_mask, end_flags_mask)   # Divide list into segments from start to end points

    return np.array(segments)


def validate_segment_mnemonics(machine_code, segments, invalid_mnemonics_mask, masking=None):
    """
    Determines whether a segment contains an invalid mnemonic and marks this segment

    :param machine_code: Sequence of hexadecimal numbers
    :param segments: A segment is defined by a sequence of the same integer
    :param invalid_mnemonics_mask: List of booleans. Determines where invalid mnemonics are located
    :param masking: List of booleans. Indicate parts of the code that should not be taken into account from the algorithm
    :return: Returns a sequence of booleans indicating whether a segment is valid or invalid
    """

    if (masking is not None):
        invalid_mnemonics_mask = np.logical_and(invalid_mnemonics_mask, masking)

    return _tag_valid_segments(segments, invalid_mnemonics_mask, invalid_indicator=True)


def validate_segment_jumps(machine_code, segments, push_data_mask, jumps_mask, masking=None):
    """
    Determines whether a segment contains a jump command that is out of range

    :param machine_code: Sequence of hexadecimal numbers
    :param segments: A segment is defined by a sequence of the same integer
    :param push_data_mask: List of booleans. Determines where push-data are located
    :param jumps_mask: List of booleans. Determines where jumps are located
    :param masking: List of booleans. Indicate parts of the code that should not be taken into account from the algorithm
    :return: Returns a sequence of booleans indicating whether a segment is valid or invalid
    """

    if (masking is not None):
        push_data_mask = np.logical_and(push_data_mask, masking)
        jumps_mask = np.logical_and(jumps_mask, masking)

    pushjumps = _get_pushjump_data(machine_code, push_data_mask, jumps_mask)    # all addresses where a push-command is followed by a jump
    invalid_jump_addresses = pushjumps[np.argwhere(pushjumps[:, 1] > len(machine_code)), 0].flatten()   # get every jump address that jumps out of scope

    invalid_jumps_mask = [False] * len(machine_code)

    for i in invalid_jump_addresses:
        invalid_jumps_mask[i] = True

    return _tag_valid_segments(segments, invalid_jumps_mask, invalid_indicator=True)


def validate_segment_jumpdests(machine_code, segments, push_data_mask, jumpdests_mask, contract_entrance_mask, masking=None):
    """
    Determines whether a segment contains a jumpdest that can be reached on the basis of the pushed data

    :param machine_code: Sequence of hexadecimal numbers
    :param segments: List of integers. A segment is defined by a sequence of the same integer
    :param push_data_mask: List of booleans. Determines where push-data are located
    :param jumpdests_mask: List of booleans. Determines where jumpdestinations are located
    :param contract_entrance_mask: List of booleans. Determines where a contract starting point is suspected
    :param masking: List of booleans. Indicate parts of the code that should not be taken into account from the algorithm
    :return: Returns a sequence of booleans indicating whether a segment is valid or invalid
    """


    if (masking is not None):
        push_data_mask = np.logical_and(push_data_mask, masking)
        jumpdests_mask = np.logical_and(jumpdests_mask, masking)

    valid_jumpdests_mask = _tag_valid_jumpdests_to_starting_points(machine_code, contract_entrance_mask,
                                                                   push_data_mask, jumpdests_mask)
    invalid_jumpdests_mask = np.logical_xor(jumpdests_mask, valid_jumpdests_mask)   # combine all findings of jumpdests with the validated jumpdests

    return _tag_valid_segments(segments, invalid_jumpdests_mask, invalid_indicator=True)


def search_contract_starts(machine_code, push_data_mask, jumpdests_mask, masking=None, stop_threshold=0.98):
    """
    Determines addresses at which a possible start of a contract is assumed

    :param machine_code: Sequence of hexadecimal numbers
    :param push_data_mask: List of booleans. Determines where push-data are located
    :param jumpdests_mask: List of booleans. Determines where jumpdestinations are located
    :param masking: List of booleans. Indicate parts of the code that should not be taken into account from the algorithm
    :param stop_threshold: Loop stop criterion. The threshold value defines the proportion of jumpdests that are reached by found entry points
    :return: List of booleans. Marks addresses at which a start of the contract is assumed
    """
    if (masking is not None):
        push_data_mask = np.logical_and(push_data_mask, masking)
        jumpdests_mask = np.logical_and(jumpdests_mask, masking)

    jumpdest_indices = np.argwhere(jumpdests_mask == True).flatten()
    push_data = _get_push_data(machine_code, push_data_mask)

    # result
    starting_points_mask = np.array([False] * len(machine_code))

    # stop criterion
    total_jumpdest_number = len(jumpdest_indices)
    total_hits = 0
    hit_ratio = 0  # ratio of jumpdests that are reachable

    while (hit_ratio < stop_threshold and len(jumpdest_indices) >= 0): # loop until a specific amount of jumpdests become valid

        bias_hits = np.zeros(len(machine_code))

        for bias in range(len(machine_code)):
            bias_hits[bias] = len(set(push_data).intersection(set(jumpdest_indices - bias)))    # count the jumpdest that are valid for a specific bias

        best_bias = bias_hits.argmax()  # find the best bias. The bias will supposed to be a contract entrance point
        hits_best_bias = bias_hits.max()

        starting_points_mask[best_bias] = True
        total_hits = total_hits + hits_best_bias
        hit_ratio = total_hits / total_jumpdest_number

        jumpdest_indices = np.array(list(set(jumpdest_indices).difference(np.array(list(set(push_data).intersection(jumpdest_indices - best_bias))) + best_bias)))  # remove findings

    return starting_points_mask


def _get_pushjump_data(machine_code, push_data_mask, jumps_mask):
    """
    Generates a list of integer values that are placed on the stack by the push data command and followed directly by a jump command

    :param machine_code: Sequence of hexadecimal numbers
    :param push_data_mask: List of booleans. Determines where push-data are located
    :param jumps_mask: List of booleans. Determines where jumps are located
    :return: Returns a nested list [[a, b] ... ] where 'a' is the jump address and 'b' is the corresponding data that is pushed
    """
    datasets_indices = hlp.get_compound_subsets(push_data_mask)
    pushjump_data = []

    for set in datasets_indices:
        set_start = set[0]
        set_end = set[-1]

        if (set_end + 1 < len(machine_code)):
            if (jumps_mask[set_end + 1]):   # validate if push instruction is followed by a jump instruction
                compound_data = hlp.compound_bytes_to_integer(machine_code[set_start:set_end + 1])
                pushjump_data.append([set_end + 1, compound_data])

    return np.array(pushjump_data)


def _tag_valid_segments(segments, validation_mask, invalid_indicator=False):
    """
    Marks all segments as true in which there are no validity violations

    :param segments: List of integers. A segment is defined by a sequence of the same integer
    :param validation_mask: List of booleans.
    :param invalid_indicator: Parameter describes the detection of an invalid address
    :return: Returns a list of booleans where all valid segments are marked with true
    """
    indices = [i for i in range(len(segments)) if validation_mask[i] == invalid_indicator]
    invalid_segment_numbers = [segments[i] for i in indices]

    valid_segments = [True] * len(segments)

    for i in range(len(segments)):
        if (segments[i] in invalid_segment_numbers):
            valid_segments[i] = False

    return np.array(valid_segments)


def _get_push_data(machine_code, push_data_mask):
    """
    Generates a list of integer values that are put on the stack by the push data command

    :param machine_code: Sequence of hexadecimal numbers
    :param push_data_mask: List of booleans. Determines where push-data are located
    :return: Returns a list of integers where each integer corresponds to data that is put on the stack
    """
    datasets_indices = hlp.get_compound_subsets(push_data_mask)
    push_data = []

    for set in datasets_indices:
        set_start = set[0]
        set_end = set[-1]

        if (set_end + 1 < len(machine_code)):
            compound_data = hlp.compound_bytes_to_integer(machine_code[set_start:set_end + 1])
            push_data.append(compound_data)

    return np.array(push_data)


def _tag_valid_jumpdests_to_starting_points(machine_code, starting_points_mask, push_data_mask, jumpdests_mask):
    """
    Returns a list of booleans that match all jumpdest that can be reached from given entry points

    :param machine_code: Sequence of hexadecimal numbers
    :param starting_points_mask: List of booleans. Determines where a contract entrance point is supposed
    :param push_data_mask: List of booleans. Determines where push-data are located
    :param jumpdests_mask: List of booleans. Determines where jumpdestinations are located
    :return: Returns a list of booleans that match all jumpdest that can be reached from given entry points
    """
    push_data = _get_push_data(machine_code, push_data_mask)
    jumpdest_indices = np.argwhere(jumpdests_mask == True).flatten()
    starting_points = np.argwhere(starting_points_mask==True).flatten()

    valid_jumpdest_mask = np.array([False] * len(machine_code))

    for bias in starting_points:
        valid_jumpdests = np.array(list(set(push_data).intersection(set(jumpdest_indices - bias)))) + bias  # find indicens

        for j in valid_jumpdests:
            valid_jumpdest_mask[j] = True

        jumpdest_indices = np.array(list(set(jumpdest_indices).difference(set(valid_jumpdests))))  # remove findings

    return valid_jumpdest_mask


