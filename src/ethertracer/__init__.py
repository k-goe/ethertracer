import ethertracer.analyzer
import ethertracer.helpers
import ethertracer.tagger
import ethertracer.opcodes
import numpy as np

def analyze(machine_code, path_save_results='ethertracer_analyze.txt'):
    """
    Analyzes an Ethereum contract and separates code from data
    :param machine_code: A list of hexadecimal numbers
    :return: A list of booleans. True for code, False for data
    """

    push_data_mask = tagger.tag_push_data(machine_code)
    invalid_mnemonic_mask = tagger.tag_invalid_mnemonics(machine_code)
    jumpdest_mask = tagger.tag_mnemonic(machine_code, "JUMPDEST")
    jump_mask = tagger.tag_mnemonic(machine_code, "JUMP")
    stop_mask = tagger.tag_mnemonic(machine_code, "STOP")
    return_mask = tagger.tag_mnemonic(machine_code, "RETURN")
    selfdestruct_mask = tagger.tag_mnemonic(machine_code, "SELFDESTRUCT")

    # Ignore findings within push-data
    invalid_mnemonic_mask = np.logical_and(invalid_mnemonic_mask, np.invert(push_data_mask))
    jumpdest_mask = np.logical_and(jumpdest_mask, np.invert(push_data_mask))
    jump_mask = np.logical_and(jump_mask, np.invert(push_data_mask))
    stop_mask = np.logical_and(stop_mask, np.invert(push_data_mask))
    return_mask = np.logical_and(return_mask, np.invert(push_data_mask))
    selfdestruct_mask = np.logical_and(selfdestruct_mask, np.invert(push_data_mask))


    # segment the machine-code
    start_flag_mask = jumpdest_mask # Marks the beginning of a segment
    end_flag_mask = np.logical_and(jump_mask, np.logical_and(stop_mask, np.logical_and(return_mask, selfdestruct_mask))) # Marks the end of a segment
    segments = analyzer.segment_code(machine_code, start_flag_mask, end_flag_mask)   # During segmentation, ignore mnemonics within push-data

    # check the segments
    mnemonic_segment_check_mask = analyzer.validate_segment_mnemonics(machine_code, segments, invalid_mnemonic_mask)
    pushjump_segment_check_mask = analyzer.validate_segment_jumps(machine_code, segments, push_data_mask, jump_mask)
    contract_starts_mask = analyzer.search_contract_starts(machine_code, push_data_mask, jumpdest_mask)
    jumpdest_segment_check_mask = analyzer.validate_segment_jumpdests(machine_code,segments, push_data_mask, jumpdest_mask, contract_starts_mask)

    # combine findings
    valid_segments_mask = np.logical_and(mnemonic_segment_check_mask, np.logical_and(pushjump_segment_check_mask, jumpdest_segment_check_mask))

    # save results as txt
    _print_results_to_txt(machine_code, push_data_mask, valid_segments_mask, contract_starts_mask, segments, mnemonic_segment_check_mask, pushjump_segment_check_mask, jumpdest_segment_check_mask, path_save_results)

    return valid_segments_mask


def _print_results_to_txt(machine_code, push_data_mask, valid_segments_mask, contract_starts_mask, segments, mnemonic_segment_check_mask, pushjump_segment_check_mask, jumpdest_segment_check_mask, path):

    conclusion = []
    for row in range(len(machine_code)):
        conclusion.append([None, None, None, None, None, None])

    column = 0
    for row in range(len(machine_code)):
        conclusion[row][column] = row

    column = 1
    contract = False
    for row in range(len(machine_code)):
        if(contract_starts_mask[row]):
            contract = True
            i=0
            conclusion[row][column] = i
            i = i + 1
        elif(contract):
            conclusion[row][column] = i
            i = i+1
        else:
            conclusion[row][column] = "x"

    column = 2
    for row in range(len(machine_code)):
        if(valid_segments_mask[row] and not push_data_mask[row]):
            conclusion[row][column] = opcodes.BYTECODES[machine_code[row]].name
        else:
            conclusion[row][column] = hex(machine_code[row])

    column = 3
    for row in range(len(machine_code)):
        if(valid_segments_mask[row]):
            conclusion[row][column] = "CODE"
        else:
            conclusion[row][column] = "DATA"

    column = 4
    for row in range(len(machine_code)):
        conclusion[row][column] = "segment " + str(segments[row])

    column = 5
    for row in range(len(machine_code)):
        if (not jumpdest_segment_check_mask[row]):
            conclusion[row][column] = "JUMPDEST NEVER REACHED"
        elif (not mnemonic_segment_check_mask[row]):
            conclusion[row][column] = "INVALID MNEMONIC OCCURS"
        elif(not pushjump_segment_check_mask[row]):
            conclusion[row][column] = "JUMP OUT OF RANGE"
        else:
            conclusion[row][column] = ' '


    conclusion.insert(0, ["Address:", "Contract Address:", "Instruction:", "Code / Data:", "Segment:", "Finding:"])
    print_conclusion = np.array(conclusion)
    np.savetxt(path, print_conclusion, fmt='%30s', delimiter=' ')


    None

