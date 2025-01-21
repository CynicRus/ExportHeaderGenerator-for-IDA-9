import ida_idaapi
import ida_frame
import ida_typeinf
import ida_name
import ida_funcs
import ida_kernwin
import ida_segment
import ida_bytes
import ida_auto
import ida_nalt
import idc

PLUGIN_NAME = "Export Header Generator by Cynic"
PLUGIN_HOTKEY = "Ctrl-Alt-H"
PLUGIN_COMMENT = "Generates C/Delphi headers from the PE exports"
PLUGIN_HELP = "This plugin analyzes exported functions and generates header files"
PLUGIN_VERSION = "1.2"

class GenerateCHeaderHandler(ida_kernwin.action_handler_t):
    def __init__(self, plugin):
        ida_kernwin.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.generate_c_header_handler()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class GenerateDelphiHeaderHandler(ida_kernwin.action_handler_t):
    def __init__(self, plugin):
        ida_kernwin.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.generate_delphi_header_handler()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ExportHeaderGenerator(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_HIDE  # Автозагрузка
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def __init__(self):
        super(ExportHeaderGenerator, self).__init__()
        self.export_list = []
        self.menu_items = []
        self.structured_data = {}
        self.enums = {}

    def init(self):
        # Создаем действия для меню
        generate_c_action = ida_kernwin.action_desc_t(
            'generate_c_header:action',
            'Generate C or C++ Header',
            GenerateCHeaderHandler(self),
            None,
            'Generate C or C++ header file',
            -1)
        
        generate_delphi_action = ida_kernwin.action_desc_t(
            'generate_delphi_header:action',
            'Generate Delphi Header',
            GenerateDelphiHeaderHandler(self),
            None,
            'Generate Delphi header file',
            -1)

        if not ida_kernwin.register_action(generate_c_action):
            print("Failed to register C or C++ header action")
        if not ida_kernwin.register_action(generate_delphi_action):
            print("Failed to register Delphi header action")

        menu_path = "Edit/Export Header Generator/"
        
        if ida_kernwin.attach_action_to_menu(
            menu_path + "Generate C or C++ Header",
            'generate_c_header:action',
            ida_kernwin.SETMENU_APP):
            self.menu_items.append('generate_c_header:action')
            
        if ida_kernwin.attach_action_to_menu(
            menu_path + "Generate Delphi Header",
            'generate_delphi_header:action',
            ida_kernwin.SETMENU_APP):
            self.menu_items.append('generate_delphi_header:action')

        return ida_idaapi.PLUGIN_KEEP  # Оставляем плагин загруженным

    def run(self, arg):
        self.generate_c_header_handler()

    def term(self):
        for item in self.menu_items:
            ida_kernwin.unregister_action(item)

    def get_demangled_name(self, name, ea):
        # деманглинг имен
        demangled = ida_name.demangle_name(name, ida_name.MNG_SHORT_FORM)
        if not demangled:
            demangled = ida_name.demangle_name(name, ida_name.MNG_LONG_FORM)
        return demangled if demangled else name

    def collect_exports(self):
        self.export_list = []
        self.collect_structures()
        self.collect_enums()
        
        for i in range(ida_name.get_nlist_size()):
            name = ida_name.get_nlist_name(i)
            ea = ida_name.get_nlist_ea(i)
            if name and ea != ida_idaapi.BADADDR:
                if ida_name.is_public_name(ea):
                    if ida_funcs.get_func(ea):
                        demangled_name = self.get_demangled_name(name, ea)
                        self.export_list.append((demangled_name, ea))

    def collect_structures(self):
        # Сбор информации о структурах
        til = ida_typeinf.get_idati()  # Получаем текущую type library
        
        # Получаем количество типов в type library
        ordinal = 1  # Начинаем с первого ординала
        max_ordinal = ida_typeinf.get_ordinal_count(til)
        
        while ordinal <= max_ordinal:
            # Получаем информацию о типе по ординалу
            tinfo = ida_typeinf.tinfo_t()
            if tinfo.get_numbered_type(til, ordinal):
                # Проверяем, является ли тип структурой
                if tinfo.is_struct():
                    # Получаем имя структуры
                    struct_name = tinfo.get_type_name()
                    if struct_name:
                        # Создаем объект tinfo_t для хранения информации о структуре
                        struct_tinfo = ida_typeinf.tinfo_t()
                        if struct_tinfo.get_named_type(til, struct_name):
                            self.structured_data[struct_name] = struct_tinfo
            
            ordinal += 1

    def collect_enums(self):
        # Получаем текущую библиотеку типов
        til = ida_typeinf.get_idati()
        # Получаем количество типов в библиотеке
        enum_count = ida_typeinf.get_ordinal_count(til)
        
        for ordinal in range(1, enum_count + 1):
            tinfo = ida_typeinf.tinfo_t()
            if tinfo.get_numbered_type(til, ordinal):
                # Проверяем, является ли тип перечислением
                if tinfo.is_enum():
                    enum_name = tinfo.get_type_name()
                    if enum_name:
                        self.enums[enum_name] = ordinal

    def analyze_function_args(self, ea):
        tinfo = ida_typeinf.tinfo_t()
        if ida_nalt.get_tinfo(tinfo, ea):
            funcdata = ida_typeinf.func_type_data_t()
            if tinfo.get_func_details(funcdata):
                args = []
                calling_convention = funcdata.cc
                for i, arg in enumerate(funcdata):
                    arg_type = str(arg.type)
                    arg_name = arg.name if arg.name else f"arg{i+1}"
                    args.append((arg_type, arg_name))
                return args, str(funcdata.rettype), calling_convention
        return self.analyze_args_by_size(ea)

    def analyze_args_by_size(self, ea):
        args = []
        t_info = ida_typeinf.tinfo_t()
        func = ida_funcs.get_func(ea)

        if func and ida_nalt.get_tinfo(t_info, ea):
            details = ida_typeinf.func_type_data_t()
            if t_info.get_func_details(details):
                arg_size = ida_bytes.get_word(ea + 2)
                current_offset = 0

                type_mapping = {
                    4: (ida_typeinf.BTF_UINT32, "DWORD"),
                    2: (ida_typeinf.BTF_UINT16, "WORD"),
                    1: (ida_typeinf.BTF_UINT8, "BYTE")
                }

                while current_offset < arg_size:
                    remaining_size = arg_size - current_offset
                    
                    # Определяем размер текущего аргумента
                    arg_size = next(size for size in [4, 2, 1] if remaining_size >= size)
                    arg_type, type_name = type_mapping[arg_size]

                    # Создаем информацию о типе аргумента
                    arg_tinfo = ida_typeinf.tinfo_t()
                    arg_tinfo.create_simple_type(arg_type)
                    
                    # Добавляем аргумент в список
                    args.append((type_name, f"arg{len(args)+1}"))
                    
                    # Обновляем информацию о типах
                    details.push_back(arg_tinfo)
                    current_offset += arg_size

        return args, "DWORD", ida_typeinf.CM_CC_STDCALL

    def generate_c_header(self):
        output = "#pragma once\n\n"
        output += f"// Generated by Export Header Generator by Cynic v{PLUGIN_VERSION}\n"
        output += f"// File: {ida_nalt.get_input_file_path()}\n"
        output += "// Warning: Some type definitions might need manual verification\n\n"
        
        # Генерация структур
        if self.structured_data:
            output += "// Structures\n"
            for name, tinfo in self.structured_data.items():
                output += f"typedef struct _{name} {{\n"
                
                # Получаем информацию о полях структуры
                udt_data = ida_typeinf.udt_type_data_t()
                if tinfo.get_udt_details(udt_data):
                    for member in udt_data:
                        member_type = str(member.type)
                        member_name = member.name
                        output += f"    {member_type} {member_name};\n"
                output += f"}} {name};\n\n"

        # Генерация перечислений
        if self.enums:
            output += "// Enumerations\n"
            for enum_name, ordinal in self.enums.items():
                tinfo = ida_typeinf.tinfo_t()
                if tinfo.get_numbered_type(ida_typeinf.get_idati(), ordinal):
                    enum_data = ida_typeinf.udt_type_data_t()
                    if tinfo.get_udt_details(enum_data):
                        output += f"typedef enum _{enum_name} {{\n"
                        for member in enum_data:
                            output += f"    {member.name} = {member.value},\n"
                        output += f"}} {enum_name};\n\n"

        output += "#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n"
        
        # Генерация прототипов функций
        for name, ea in self.export_list:
            args, ret_type, cc = self.analyze_function_args(ea)
            args_str = ", ".join([f"{type} {name}" for type, name in args]) or "void"
            
            # Получение комментария функции
            func = ida_funcs.get_func(ea)
            if func:
                cmt = ida_funcs.get_func_cmt(func, False)
                if cmt:
                    output += f"// {cmt}\n"
            
            cc_str = "__stdcall" if cc == ida_typeinf.CM_CC_STDCALL else "__cdecl"
            output += f"{ret_type} {cc_str} {name}({args_str});\n\n"
        
        output += "#ifdef __cplusplus\n}\n#endif\n"
        return output
        
    def _is_large_structure(self, type_name):
        if type_name in self.structured_data:
            # Подсчет размера структуры
            size = 0
            tinfo = self.structured_data[type_name]
            udt_data = ida_typeinf.udt_type_data_t()
            if tinfo.get_udt_details(udt_data):
                for member in udt_data:
                    size += member.type.get_size()
            return size > 16  # Пороговое значение для больших структур
        return False
        
    def format_delphi_arguments(self, args):
        formatted_args = []
        for arg_type, arg_name in args:
            # Преобразуем тип C в тип Delphi
            delphi_type = self.c_to_delphi_type(arg_type)
            
            # Обработка указателей без использования var
            if arg_type.endswith('*') or 'void *' in arg_type:
                delphi_type = 'Pointer'
            
            # Обработка строковых типов
            elif arg_type in ['char *', 'TCHAR *', 'LPSTR', 'LPCSTR']:
                delphi_type = 'PAnsiChar'
            elif arg_type in ['wchar_t *', 'LPWSTR', 'LPCWSTR']:
                delphi_type = 'PWideChar'
                
            # Обработка массивов
            elif '[' in delphi_type:
                size = delphi_type[delphi_type.find('[')+1:delphi_type.find(']')]
                base_type = delphi_type[:delphi_type.find('[')]
                delphi_type = f'array[0..{int(size)-1}] of {self.c_to_delphi_type(base_type)}'
                
            # Добавление const для строк и больших структур
            if delphi_type in ['String', 'AnsiString', 'WideString'] or self._is_large_structure(arg_type):
                formatted_args.append(f'const {arg_name}: {delphi_type}')
            else:
                formatted_args.append(f'{arg_name}: {delphi_type}')
        
        return '; '.join(formatted_args)


    def generate_delphi_header(self):
        unit_name = ida_nalt.get_root_filename().split('.')[0]
        output = f"unit {unit_name}Exports;\n\n"
        output += "interface\n\n"
        output += f"// Generated by Export Header Generator by Cynic v{PLUGIN_VERSION}\n"
        output += f"// File: {ida_nalt.get_input_file_path()}\n"
        output += "// Warning: Some type definitions might need manual verification\n\n"
        
        if self.structured_data or self.enums:
            output += "type\n"
            
            # Генерация структур
            for name, tinfo in self.structured_data.items():
                output += f"  {name} = record\n"
                udt_data = ida_typeinf.udt_type_data_t()
                if tinfo.get_udt_details(udt_data):
                    for member in udt_data:
                        member_type = self.c_to_delphi_type(str(member.type))
                        member_name = member.name
                        output += f"    {member_name}: {member_type};\n"
                output += "  end;\n\n"

            # Генерация перечислений
            for enum_name, ordinal in self.enums.items():
                tinfo = ida_typeinf.tinfo_t()
                if tinfo.get_numbered_type(ida_typeinf.get_idati(), ordinal):
                    enum_data = ida_typeinf.udt_type_data_t()
                    if tinfo.get_udt_details(enum_data):
                        output += f"  {enum_name} = (\n"
                        for i, member in enumerate(enum_data):
                            comma = "," if i < len(enum_data) - 1 else ""
                            output += f"    {member.name} = {member.value}{comma}\n"
                        output += "  );\n\n"

        # Генерация прототипов функций
        for name, ea in self.export_list:
            args, ret_type, cc = self.analyze_function_args(ea)
            ret_type = self.c_to_delphi_type(ret_type)
            
            # Получение комментария функции
            func = ida_funcs.get_func(ea)
            if func:
                cmt = ida_funcs.get_func_cmt(func, False)
                if cmt:
                    output += f"// {cmt}\n"
            
            args_str = self.format_delphi_arguments(args)
            if ret_type.lower() == "void":
                output += f"procedure {name}({args_str}); stdcall; external '{unit_name}';\n"
            else:
                output += f"function {name}({args_str}): {ret_type}; stdcall; external '{unit_name}';\n"
        
        output += "\nimplementation\n\nend.\n"
        return output

    def c_to_delphi_type(self, c_type):
        # Расширенная карта соответствия типов
        type_map = {
            "void": "procedure",
            "DWORD": "Cardinal",
            "WORD": "Word",
            "BYTE": "Byte",
            "char *": "PAnsiChar",
            "const char *": "PAnsiChar",
            "TCHAR *": "PWideChar",
            "const TCHAR *": "PWideChar",
            "wchar_t *": "PWideChar",
            "const wchar_t *": "PWideChar",
            "int": "Integer",
            "unsigned int": "Cardinal",
            "long": "LongInt",
            "unsigned long": "Cardinal",
            "short": "SmallInt", 
            "unsigned short": "Word",
            "float": "Single",
            "double": "Double",
            "bool": "Boolean",
            "BOOL": "LongBool",
            "HANDLE": "THandle",
            "HINSTANCE": "HINST",
            "LPVOID": "Pointer",
            "void *": "Pointer",
            "PVOID": "Pointer",
            "HWND": "HWND",
            "UINT": "Cardinal",
            "DWORD *": "PCardinal",
            "WORD *": "PWord",
            "BYTE *": "PByte",
            "int *": "PInteger",
            "float *": "PSingle",
            "double *": "PDouble",
            "char **": "PPAnsiChar",
            "TCHAR **": "PPWideChar",
            "SIZE_T": "NativeUInt",
            "LONG": "LongInt",
            "ULONG": "Cardinal",
            "LONGLONG": "Int64",
            "ULONGLONG": "UInt64",
            "INT_PTR": "NativeInt",
            "UINT_PTR": "NativeUInt",
            "LONG_PTR": "NativeInt",
            "ULONG_PTR": "NativeUInt",
            "__int64": "Int64",
            "unsigned __int64": "UInt64"
        }

        # Обработка указателей
        if c_type.endswith('*'):
            base_type = c_type[:-1].strip()
            if base_type in type_map:
                return f"P{type_map[base_type]}"
            return "Pointer"
        
        # Обработка массивов
        if '[' in c_type:
            array_base = c_type[:c_type.find('[')].strip()
            array_size = c_type[c_type.find('[')+1:c_type.find(']')]
            if not array_size.isdigit():
                array_size = '0'
            base_type = self.c_to_delphi_type(array_base)
            return f"array[0..{int(array_size)-1}] of {base_type}"

        # Обработка const
        if c_type.startswith('const '):
            return self.c_to_delphi_type(c_type[6:])

        return type_map.get(c_type, c_type)

    def save_header_file(self, content, default_ext):
        file_name = ida_kernwin.ask_file(True, f"*.{default_ext}", f"Save {default_ext.upper()} header file")
        if file_name:
            try:
                with open(file_name, 'w') as f:
                    f.write(content)
                print(f"Header file saved successfully to: {file_name}")
            except Exception as e:
                print(f"Error saving file: {str(e)}")

    def generate_c_header_handler(self):
        self.collect_exports()
        output = self.generate_c_header()
        self.save_header_file(output, "h")

    def generate_delphi_header_handler(self):
        self.collect_exports()
        output = self.generate_delphi_header()
        self.save_header_file(output, "pas")
        
def PLUGIN_ENTRY():
    return ExportHeaderGenerator()
