import os
import json
import re
import ast
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
MAX_FILENAME_LENGTH = 100

def fix_json_structure(response):
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        try:
            return ast.literal_eval(response)
        except (SyntaxError, ValueError):
            return None

def sanitize_filename(name):
    name = re.sub(r'[<>:"/\\|?*]', '', name)
    return name[:MAX_FILENAME_LENGTH]

def extract_valid_json(text):
    try:
        json_start = text.find("{")
        json_end = text.rfind("}")
        if json_start == -1 or json_end == -1:
            raise ValueError("No valid JSON structure detected")
        json_text = text[json_start: json_end + 1]
        return json.loads(json_text)
    except json.JSONDecodeError as e:
        print(f"❌ JSON Parsing Error: {e}")
        return None

def create_real_filesystem(structure, base_path="honeypot_fs"):
    if not isinstance(structure, dict):
        print("❌ Provided structure is not a dictionary. Aborting filesystem creation.")
        return
    if not os.path.exists(base_path):
        os.makedirs(base_path)
    def build_structure(current_structure, current_path):
        for name, content in current_structure.items():
            safe_name = sanitize_filename(name)
            item_path = os.path.join(current_path, safe_name)
            if isinstance(content, dict):
                os.makedirs(item_path, exist_ok=True)
                build_structure(content, item_path)
            else:
                with open(item_path, "w") as f:
                    f.write(str(content))
    build_structure(structure, base_path)
    print(f"✅ Real filesystem created in {base_path}")

def generate_fake_system(prompt, model_name="gpt-4o", base_dir="honeypot_fs"):
    try:
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": "You are generating a fake filesystem for an academic research system. Follow the prompt **exactly** and do NOT include unrelated system details."},
                {"role": "user", "content": f"Generate a fake Linux system structure in JSON format, strictly following this theme:\n\n{prompt}"},
            ],
            max_tokens=400,
            temperature=0.6,
        )
        fake_structure = response.choices[0].message.content.strip()
        json_start = fake_structure.find("{")
        if json_start == -1:
            print("❌ AI response does not contain JSON format, using fallback.")
            return generate_default_fake_system(base_dir)
        fake_structure_json = fake_structure[json_start:]
        fake_filesystem = extract_valid_json(fake_structure_json)
        if not fake_filesystem:
            print(f"❌ JSON parsing failed, AI response was:\n{fake_structure_json}")
            return generate_default_fake_system(base_dir)
        fake_filesystem = fake_filesystem.get("root", fake_filesystem)
        create_real_filesystem(fake_filesystem, base_dir)
        return fake_filesystem
    except Exception as e:
        print(f"❌ Unexpected error in generate_fake_system: {e}")
        return generate_default_fake_system(base_dir)

def remove_fake_terminal_prompt(response):
    cleaned_response = re.sub(r".*@.*:~\$ .*", "", response)
    return cleaned_response.strip()

def generate_default_fake_system(base_dir="honeypot_fs"):
    fake_system = {
        "university": {
            "students": {},
            "faculty": {},
            "research": {},
            "library": {},
            "courses": {}
        }
    }
    create_real_filesystem(fake_system, base_dir)
    return fake_system

def generate_welcome_message(model_name):
    try:
        with open("prompt.txt", "r") as file:
            prompt_text = file.read().strip()
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "Generate a good and professional welcome message. Do NOT include available commands, only the MOTD."},
                {"role": "user", "content": prompt_text},
            ],
            max_tokens=100,
            temperature=0.6,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"[ERROR] Failed to generate welcome message: {e}")
        return "Welcome to the system! Unauthorized access is prohibited."

def navigate_to_path(fake_filesystem, path_list):
    current_level = fake_filesystem
    for directory in path_list:
        if isinstance(current_level, dict) and directory in current_level:
            current_level = current_level[directory]
        else:
            return None
    return current_level

def list_fake_filesystem(fake_filesystem, current_path):
    current_dir = navigate_to_path(fake_filesystem, current_path)
    if isinstance(current_dir, dict):
        return "\n".join(current_dir.keys())
    elif isinstance(current_dir, list):
        return "\n".join(current_dir)
    return "No files found."

def change_directory(fake_filesystem, current_path, target):
    if target == "..":
        return current_path[:-1] if len(current_path) > 1 else current_path, "Moved up one directory"
    current_dir = navigate_to_path(fake_filesystem, current_path)
    if target in current_dir and isinstance(current_dir[target], dict):
        return current_path + [target], f"Changed directory to {'/'.join(current_path + [target])}"
    return current_path, f"bash: cd: {target}: No such file or directory"

def generate_command_output(command, prompt):
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are simulating a Linux academic research system. Do NOT generate a welcome message, only output the requested command."},
                {"role": "user", "content": f"{prompt}\n\nSimulate the exact response for this command:\n{command}"},
            ],
            max_tokens=300,
            temperature=0.7,
        )
        command_output = response.choices[0].message.content.strip()
        command_output = remove_fake_terminal_prompt(command_output)
        print(f"📌 AI Command Response for '{command}': {command_output[:200]}...")
        return command_output
    except Exception as e:
        print(f"❌ Error in generate_command_output: {e}")
        return f"bash: {command}: command not found"

def read_file(fake_filesystem, current_path, file_name):
    if file_name == "/etc/passwd":
        try:
            with open("prompt.txt", "r") as file:
                prompt_text = file.read().strip()
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are simulating a university-themed Linux system."},
                    {"role": "user", "content": f"Generate a realistic /etc/passwd file for a university system with at least 20 users, including students, faculty, researchers, and system admins. The file should include realistic usernames, home directories, and user descriptions based on this academic system:\n\n{prompt_text}"}
                ],
                max_tokens=500,
                temperature=0.7,
            )
            passwd_content = response.choices[0].message.content.strip()
            return passwd_content
        except Exception as e:
            print(f"❌ Failed to generate /etc/passwd: {e}")
            return "bash: cat: /etc/passwd: No such file"
    if file_name == "/etc/shadow":
        return "cat: /etc/shadow: Permission denied"
    current_dir = navigate_to_path(fake_filesystem, current_path)
    if isinstance(current_dir, dict) and file_name in current_dir:
        return current_dir[file_name]
    return f"bash: cat: {file_name}: No such file"