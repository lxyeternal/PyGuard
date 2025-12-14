import os

class Config:

    AZURE_OPENAI_API_KEY = "6mGBoCQqU4bVMKehRuSP25ltTIXV=J3w3AAABACOG0VFv"
    AZURE_OPENAI_ENDPOINT = "https://malicious-intelligence.openai.azure.com/"
    AZURE_OPENAI_API_VERSION = "2025-01-01-preview"
    

    STRONG_MODEL = "gpt-4.1"

    STANDARD_MODEL = "gpt-4.1-nano"
    

    STANDARD_MODEL_REPORTS_COUNT = 5 

    STRONG_MODEL_REPORTS_COUNT = 3  
    

    STEP1_PARAMS = {"temperature": 1.0, "top_p": 0.9}
    STEP2_PARAMS = {"temperature": 0.75, "top_p": 0.6}
    STEP3_PARAMS = {"temperature": 0.5, "top_p": 0.5}
    

    MALWARE_THRESHOLD = 0.5
    

    USER_PROMPT = "Analyze the above code for malicious behavior. Remember to respond in the required JSON format. Consider ALL of the code carefully. Check the beginning, middle, and end of the code. Work step-by-step to get the right answer."
    

    DATASETS = {
        "evaluation": {
            "benign": "/home2/blue/Documents/PyPIAgent/Dataset/evaluation/unzip_benign",
            "malware": "/home2/blue/Documents/PyPIAgent/Dataset/evaluation/unzip_malware",
            "output_benign": "/home2/blue/Documents/PyPIAgent/Codes/tool_detect/detect_output/baselines/evaluation/socketai/benign",
            "output_malware": "/home2/blue/Documents/PyPIAgent/Codes/tool_detect/detect_output/baselines/evaluation/socketai/malware"
        },
        "latest": {
            "benign": "/home2/blue/Documents/PyPIAgent/Dataset/latest/unzip_benign",
            "malware": "/home2/blue/Documents/PyPIAgent/Dataset/latest/unzip_malware",
            "output_benign": "/home2/blue/Documents/PyPIAgent/Codes/tool_detect/detect_output/baselines/latest/socketai/benign",
            "output_malware": "/home2/blue/Documents/PyPIAgent/Codes/tool_detect/detect_output/baselines/latest/socketai/malware"
        },
        "obfuscation": {
            "benign": "/home2/blue/Documents/PyPIAgent/Dataset/obfuscation/unzip_benign",
            "malware": "/home2/blue/Documents/PyPIAgent/Dataset/obfuscation/unzip_malware",
            "output_benign": "/home2/blue/Documents/PyPIAgent/Codes/tool_detect/detect_output/baselines/obfuscation/socketai/benign",
            "output_malware": "/home2/blue/Documents/PyPIAgent/Codes/tool_detect/detect_output/baselines/obfuscation/socketai/malware"
        }
    }
    

    BENIGN_DATASET_PATH = DATASETS["evaluation"]["benign"]
    MALWARE_DATASET_PATH = DATASETS["evaluation"]["malware"]
    BENIGN_OUTPUT_PATH = DATASETS["evaluation"]["output_benign"]
    MALWARE_OUTPUT_PATH = DATASETS["evaluation"]["output_malware"]

    MAX_FILE_SIZE = 175 * 1024
    
    MAX_PY_FILES_PER_PACKAGE = 30
    
    PROCESS_COUNT = 10