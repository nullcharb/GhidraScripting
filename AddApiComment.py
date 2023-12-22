from ghidra.program.model.symbol import RefType
import json

def read_json_file(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            return data
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return None


def find_move_instruction(instruction, api_hash_dict):
    i = 0
    ins = instruction.getPrevious()
    api_hash = ""
    
    for i in range(0,5,1):
        
        pneumonic = ins.getMnemonicString()
        print(f"pneumonic :{pneumonic}")
        
        if pneumonic == "MOV":
            print(f"Address : {ins.getAddress()}")
            operand1 = ins.getOpObjects(0)
            op1 = [str(operand) for operand in operand1]
            print(f"Op1 : {op1}")
            
            if op1[0] == "EDX":            
                operand2 = ins.getOpObjects(1)
                op2 = [str(operand) for operand in operand2]
                print(f"Op2 : {op2[0]}")
                api_hash = op2[0]
                break
        print("Going to previous")
        ins = ins.getPrevious()
    if api_hash in api_hash_dict:
        print(f"Api : {api_hash_dict[api_hash]}")
        return api_hash_dict[api_hash]
    # ins.setComment(ins.EOL_COMMENT,"")
    

# Example usage:
file_path = 'C:\\Users\\Developer\\Desktop\\GhidraScripting\\exports.json'  # Replace with the path to your JSON file
api_hash_data = read_json_file(file_path)

function_name = "getFunctionAddressByHash"

function = getGlobalFunctions(function_name)

for item in function:
    address = item.getEntryPoint()

references = getReferencesTo(address)

for ref in references:
    # Check if the reference type is a call reference (you can adjust this condition as needed)
    if ref.getReferenceType() == RefType.UNCONDITIONAL_CALL:
        print("Reference at address:", ref.getFromAddress())
        caller_address = ref.getFromAddress()
        caller_instruction = currentProgram().getListing().getInstructionAt(caller_address)
        print(caller_instruction.getMnemonicString())
        api = find_move_instruction(caller_instruction, api_hash_data)
        caller_instruction.setComment(caller_instruction.PRE_COMMENT,api)