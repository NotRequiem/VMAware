import questionary
import sys
import os

is_dev_mode = len(sys.argv) > 1 and sys.argv[1] == "--dev"
tab = "    "


class Options:
    def __init__(self, enum_name, file_path, function_name, cross_platform, is_linux, is_win, is_mac, score, short_description, description, author, link, is_admin, only_32_bit, is_x86_only, notes):
        self.enum_name = enum_name
        self.file_path = file_path
        self.function_name = function_name
        self.cross_platform = cross_platform
        self.is_linux = is_linux
        self.is_win = is_win
        self.is_mac = is_mac
        self.score = score
        self.short_description = short_description
        self.description = description
        self.author = author
        self.link = link
        self.is_admin = is_admin
        self.only_32_bit = only_32_bit
        self.is_x86_only = is_x86_only
        self.notes = notes


def prompt():
    # 1: Enum name
    if is_dev_mode:
        enum_answer = "TEST"
    else:
        enum_answer = questionary.text("What's the name of the enum? (e.g. VBOX_REG or HYPERVISOR_STR)").ask()
        enum_answer = enum_answer.upper().strip()

    # 2: Technique file
    if is_dev_mode:
        file_path = "../archive/techniques/test.cpp"
    else:
        while True:
            file_path = questionary.path("What's the path to the technique file?").ask()
            if not file_path.endswith((".cpp", ".cc")):
                print("File input must be a .cpp or .cc file.")
                continue

            with open(file_path, 'r', encoding='utf-8') as file:
                has_valid_specifier = False
                has_include = False
                for line in file:
                    if "#include" in line.lower():
                        has_include = True
                    if "VMAWARE_TECHNIQUE" in line or "static" in line:
                        has_valid_specifier = True

                if has_include:
                    print("Do not include #include headers in the snippet file; it will be directly pasted into the header.")
                    continue

                if not has_valid_specifier:
                    print("The function must be declared with VMAWARE_TECHNIQUE (or static).")
                    continue
                break

    # 3: Function name
    if is_dev_mode:
        function_name = "test"
    else:
        function_name = questionary.text("What's the name of the function in your file? (e.g. new_technique())").ask()
        function_name = function_name.lower().replace("(", "").replace(")", "").strip()

    # 4: Platform support
    if is_dev_mode:
        cross_platform = False
        is_linux = True
        is_win = False
        is_mac = False
    else:
        cross_platform = questionary.confirm("Is it cross-platform?").ask()
        is_linux, is_win, is_mac = False, False, False
        if cross_platform:
            is_linux, is_win, is_mac = True, True, True
        else:
            choices = questionary.checkbox(
                "Which OS does this technique support?",
                choices=["Linux", "Windows", "MacOS"]
            ).ask()
            if "Linux" in choices:
                is_linux = True
            if "Windows" in choices:
                is_win = True
            if "MacOS" in choices:
                is_mac = True

    # 5: Score (0 - 300)
    if is_dev_mode:
        score = 50
    else:
        while True:
            certainty = questionary.text("What's the score of your technique? (0-300)").ask()
            if certainty.isdigit() and 0 <= int(certainty) <= 300:
                score = int(certainty)
                break
            print("Score must be a number between 0 and 300, try again.")

    # 6: Description
    if is_dev_mode:
        description = "testing, this is a boilerplate technique"
    else:
        while True:
            text = questionary.text("What's the description of your technique? (30-100 characters)").ask()
            if 30 <= len(text) <= 100:
                description = text
                break
            print("Description must be between 30 and 100 characters.\n")

    # 7: Short description
    if is_dev_mode:
        short_description = "testing, ignore"
    else:
        while True:
            text = questionary.text("What is your technique checking for? (CLI display, max 25 chars)").ask()
            if len(text) <= 25 and len(text) <= len(description):
                short_description = text
                break
            print("Short description must be <= 25 characters and shorter than the main description.\n")

    # 8-12: Optional metadata
    author = "" if is_dev_mode else questionary.text("Author name (optional):").ask()
    link = "" if is_dev_mode else questionary.text("Source/origin link (optional):").ask()
    is_admin = False if is_dev_mode else questionary.confirm("Requires admin/root privileges?").ask()
    only_32_bit = False if is_dev_mode else questionary.confirm("Is it 32-bit only?").ask()
    is_x86 = True if is_dev_mode else questionary.confirm("Is it x86-only? (no ARM support)").ask()
    notes = "" if is_dev_mode else questionary.text("Extra notes (optional):").ask()

    return Options(
        enum_answer,
        file_path,
        function_name,
        cross_platform,
        is_linux,
        is_win,
        is_mac,
        score,
        short_description,
        description,
        author,
        link,
        is_admin,
        only_32_bit,
        is_x86,
        notes
    )


def write_header(options, header_file):
    if not os.path.exists(header_file):
        print(f"Error: {header_file} does not exist.")
        return

    with open(header_file, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    new_code = []

    # Check which marker comments currently exist in the header
    has_enum_marker = any("// ADD NEW TECHNIQUE ENUM NAME HERE" in l for l in lines)
    has_func_marker = any("// ADD NEW TECHNIQUE FUNCTION HERE" in l for l in lines)
    has_table_marker = any("// END OF TECHNIQUE TABLE" in l or "// ADD NEW TECHNIQUE TO TABLE" in l for l in lines)
    has_case_marker = any("// ADD NEW CASE HERE" in l for l in lines)

    # Technique function comments (all using // comments)
    technique_details = ["// @brief " + options.description]
    if options.author:
        technique_details.append("// @author " + options.author)
    if options.link:
        technique_details.append("// @link " + options.link)

    category_list = []
    if options.cross_platform:
        if options.is_x86_only:
            category_list.append("x86")
    else:
        if options.is_linux:
            category_list.append("Linux")
        if options.is_win:
            category_list.append("Windows")
        if options.is_mac:
            category_list.append("MacOS")
    if category_list:
        technique_details.append("// @category " + ", ".join(category_list))

    if options.notes:
        technique_details.append("// @note " + options.notes)
    technique_details.append("// @implements VM::" + options.enum_name)

    # Read and normalize the snippet code to use VMAWARE_TECHNIQUE
    with open(options.file_path, 'r', encoding='utf-8') as tf:
        technique_code = tf.readlines()

    for idx, t_line in enumerate(technique_code):
        if "[[nodiscard]] static vmaware_technique" in t_line:
            technique_code[idx] = t_line.replace("[[nodiscard]] static vmaware_technique", "VMAWARE_TECHNIQUE")
        elif "static vmaware_technique" in t_line and "VMAWARE_TECHNIQUE" not in t_line:
            technique_code[idx] = t_line.replace("static vmaware_technique", "VMAWARE_TECHNIQUE")

    # Format the complete technique block
    technique_block = ["\n"] + [c + "\n" for c in technique_details]
    preprocessors = ["#endif", "#elif", "#else", "#if"]
    for t_line in technique_code:
        if any(sub in t_line for sub in preprocessors):
            technique_block.append(t_line.lstrip())
        else:
            technique_block.append(tab + t_line)
    technique_block.append("\n\n")

    # Table entry string
    table_entry_str = tab + tab + f"{{ VM::{options.enum_name}, {{ {options.score}, VM::{options.function_name} }} }},\n"
    case_str = tab + tab + tab + f'case {options.enum_name}: return "{options.enum_name}";\n'

    in_get_technique_table = False
    in_entries_array = False
    table_entry_inserted = False
    func_inserted = False
    enum_inserted = False
    case_inserted = False

    for line in lines:
        # 1. Enum insertion
        if has_enum_marker and "// ADD NEW TECHNIQUE ENUM NAME HERE" in line and not enum_inserted:
            new_code.append(tab + tab + options.enum_name + ",\n")
            enum_inserted = True
        elif not has_enum_marker and "DEFAULT," in line and not enum_inserted:
            new_code.append(tab + tab + options.enum_name + ",\n")
            enum_inserted = True

        # 2. Function definition insertion
        if has_func_marker and "// ADD NEW TECHNIQUE FUNCTION HERE" in line and not func_inserted:
            new_code.extend(technique_block)
            func_inserted = True
        elif not has_func_marker and "struct core {" in line and not func_inserted:
            new_code.extend(technique_block)
            func_inserted = True

        # Track location inside get_technique_table()
        if "get_technique_table()" in line:
            in_get_technique_table = True
        if in_get_technique_table and "entries[]" in line:
            in_entries_array = True

        # 3. Technique table entry insertion
        if has_table_marker and any(m in line for m in ["// END OF TECHNIQUE TABLE", "// ADD NEW TECHNIQUE TO TABLE"]) and not table_entry_inserted:
            new_code.append(table_entry_str)
            table_entry_inserted = True
        elif not has_table_marker and in_entries_array and "};" in line and not table_entry_inserted:
            new_code.append(table_entry_str)
            table_entry_inserted = True
            in_entries_array = False
            in_get_technique_table = False

        # 4. flag_to_string() case insertion
        if has_case_marker and "// ADD NEW CASE HERE" in line and not case_inserted:
            new_code.append(case_str)
            case_inserted = True
        elif not has_case_marker and "case DEFAULT:" in line and not case_inserted:
            new_code.append(case_str)
            case_inserted = True

        new_code.append(line)

    with open(header_file, "w", encoding='utf-8') as file:
        file.writelines(new_code)
    print(f"Updated {header_file}")


def write_cli(options):
    cli_path = '../src/cli.cpp'
    if not os.path.exists(cli_path):
        return

    with open(cli_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    new_code = []

    for line in lines:
        if "// ADD NEW TECHNIQUE CHECKER" in line:
            new_code.append(tab + f'checker(VM::{options.enum_name}, "{options.short_description}");\n')

        if "// ADD LINUX FLAG" in line and options.is_linux:
            new_code.append(tab + tab + tab + f"case VM::{options.enum_name}:\n")

        if "// ADD WINDOWS FLAG" in line and options.is_win:
            new_code.append(tab + tab + tab + f"case VM::{options.enum_name}:\n")

        if "// ADD MACOS FLAG" in line and options.is_mac:
            new_code.append(tab + tab + tab + f"case VM::{options.enum_name}:\n")

        new_code.append(line)

    with open(cli_path, "w", encoding='utf-8') as file:
        file.writelines(new_code)
    print("Updated CLI (../src/cli.cpp)")


def write_docs(options):
    doc_path = '../docs/documentation.md'
    if not os.path.exists(doc_path):
        return

    with open(doc_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    new_docs = []
    updated = False

    # Build platform string
    if options.cross_platform:
        platform_icons = "🐧🪟🍏"
    else:
        icons = []
        if options.is_linux:
            icons.append("🐧")
        if options.is_win:
            icons.append("🪟")
        if options.is_mac:
            icons.append("🍏")
        platform_icons = "".join(icons)

    # 8-column row format:
    # | Flag alias | Description | Supported platforms | Certainty | Admin? | 32-bit only? | Notes | Code implementation |
    admin_str = "Admin" if options.is_admin else ""
    bit32_str = "32-bit" if options.only_32_bit else ""
    notes_str = options.notes if options.notes else ""
    row