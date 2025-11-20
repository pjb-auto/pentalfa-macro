# Pentalfa Macro

A Python automation tool that detects and automatically clicks the "Afspelen" (Play) button on screen using computer vision.

## Features

- **Smart Detection**: Uses OpenCV template matching to detect the target button with high accuracy
- **Adaptive Scanning**: Dynamically adjusts search regions based on button location
- **Security Checks**: Built-in anti-debugging and virtualization detection
- **User-Friendly GUI**: Clean dashboard with real-time status updates and click counter
- **Fail-Safe**: PyAutoGUI fail-safe feature (move mouse to top-left corner to abort)

## Requirements

- Python 3.8+
- Windows OS (due to security checks and GUI optimizations)
- Required Python packages (see `requirements.txt`)

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/pentalfa_macro.git
   cd pentalfa_macro
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Ensure the `afspelen.png` template image is in the project directory

## Usage

### Running from Source
```bash
python afspelen.py
```

### Building Executable
```bash
python build.py
```
This will create a standalone executable in the `dist/` directory.

## How It Works

1. **Template Matching**: The application loads a template image (`afspelen.png`) and continuously scans the screen for matches
2. **Adaptive Region**: Initially scans a centered region of the screen, then adapts based on where buttons are found
3. **Smart Clicking**: Only clicks when a button is newly detected (prevents spam clicking)
4. **Fail-Safe Expansion**: If the button isn't found after several attempts, expands to full-screen scanning

## Configuration

Key parameters can be adjusted in `afspelen.py`:

- `SCAN_INTERVAL`: Time between scans (default: 5.0 seconds)
- `REGION_SCALE`: Portion of screen to scan initially (default: 0.4)
- `MATCH_THRESHOLD`: Template matching confidence threshold (default: 0.85)
- `MAX_MISSES_BEFORE_EXPAND`: Misses before full-screen scan (default: 3)

## Security Features

The application includes several security measures:
- Debugger detection
- Virtual machine detection
- Anti-analysis checks

To bypass security checks for development, set the environment variable:
```bash
set PENTALFA_ALLOW_UNSAFE=1
```

## GUI Controls

- **▶ Start**: Begin scanning for the target button
- **■ Stop**: Pause scanning
- **Click Counter**: Shows total number of successful clicks
- **Status Display**: Real-time feedback on scanning status

## Building for Distribution

The `build.py` script uses PyInstaller to create a standalone executable with:
- Single-file packaging
- No console window
- Asset bundling
- Code optimization
- Optional bytecode encryption (PyInstaller < 6.0)

## Troubleshooting

- **Template not found**: Ensure `afspelen.png` is in the same directory as the script
- **No clicks registered**: Adjust `MATCH_THRESHOLD` if the template matching is too strict
- **Security violation**: Run with `PENTALFA_ALLOW_UNSAFE=1` for development/testing

## License

This project is for educational and automation purposes. Use responsibly and in accordance with the terms of service of any applications you interact with.
