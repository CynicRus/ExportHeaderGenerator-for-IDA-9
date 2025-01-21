# Export Header Generator Plugin for IDA Pro

## Description
A Python plugin for IDA Pro that automatically generates C/C++ and Delphi header files from PE exports. The plugin analyzes exported functions, structures, and enumerations in the binary file and creates corresponding header declarations.
Currently only ida 9 is supported.

## Key Features
- Generates both C/C++ (.h) and Delphi (.pas) header files
- Supports function exports analysis with parameter detection
- Handles structures and enumerations
- Performs name demangling
- Includes type conversion between C/C++ and Delphi
- Supports various Windows-specific types
- Adds function comments from IDA to generated headers
- Integrates into IDA's Edit menu

## How to Use

1. **Installation**:
   - Place the plugin file in IDA Pro's plugins directory
   - Plugin will be automatically loaded when IDA starts

2. **Using the Plugin**:
   - Access via Edit -> Export Header Generator menu
   - Choose between "Generate C or C++ Header" or "Generate Delphi Header"
   - Select destination file location when prompted
   - Generated header will include all exported functions with proper signatures

3. **Hotkey**:
   - Default hotkey: Ctrl-Alt-H
   - Triggering hotkey generates C/C++ header by default

4. **Output**:
   - Headers include file metadata and generation info
   - Structures and enumerations are placed at the beginning
   - Function prototypes follow with proper calling conventions
   - Comments from IDA are preserved in the generated files
      
