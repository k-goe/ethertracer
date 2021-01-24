def bitsring_to_bytes(bitstring):
    """
    Converts a string of bits to a list of bytes
    :param bits: String of bits
    :return: List of Bytes as integers
    """
    list_of_bytes = list(bytes(int(bitstring[i: i + 8], 2) for i in range(0, len(bitstring), 8)))
    return list_of_bytes


def hexstring_to_bytes(hexstring):
    """
    Converts a string of hex-numbers to a list of bytes

    :param hexstring: String of hex-numbers
    :return: List of Bytes as integers
    """

    list_of_bytes = list(bytes(int(hexstring[i: i + 2], 16) for i in range(0, len(hexstring), 2)))
    return list_of_bytes


def get_compound_subsets(list, indicator=True):
    """
    Divides a list into related parts

    :param list: List to be subdivided
    :param indicator: Specifies which value is to be combined into a sequence
    :return: Returns a nested list in which each entry marks a connected segment with all addresses
    """
    index_subset_element = []

    for i in range(len(list)):
        if (list[i] == indicator):
            index_subset_element.append(i)

    number_of_subsets = 0
    subsets = []

    for i in range(len(index_subset_element)):

        subsets.append(number_of_subsets)

        if (i < len(index_subset_element) - 1):
            if (index_subset_element[i + 1] - index_subset_element[i] > 1):
                number_of_subsets = number_of_subsets + 1

    subsets_indices = []  # result

    for i in range(number_of_subsets + 1):

        temp_splitted_element_indices = []

        for j in range(len(subsets)):
            if (subsets[j] == i):
                temp_splitted_element_indices.append(index_subset_element[j])

        subsets_indices.append(temp_splitted_element_indices)

    return subsets_indices


def compound_bytes_to_integer(bytes):
    """
    Links a list of bytes to one integer

    :param bytes: list of bytes
    :return: integer that is compound of given bytes
    """

    n = len(bytes)
    bit_list = []

    for i in range(n):
        bit_list.append(f'{bytes[i]:08b}')

    compound_bits = ''.join(bit_list)
    compound_int = int(compound_bits, 2)

    return compound_int


def segment_list(flags_segment_start, flags_segment_end):
    """
    Divides a list into segments that are determined by the given start and end points

    :param flags_segment_start: List of booleans. Determines all segment start points
    :param flags_segment_end:  List of booleans. Determines all segment end points
    :return: Returns a list of integers where every integer determines a segment
    """

    segments = []
    segment_counter = 0

    for i in range(len(flags_segment_start)):

        if (flags_segment_start[i]):
            segment_counter = segment_counter + 1
            segments.append(segment_counter)

        elif (flags_segment_end[i]):
            segments.append(segment_counter)
            segment_counter = segment_counter + 1
        else:
            segments.append(segment_counter)

    return segments