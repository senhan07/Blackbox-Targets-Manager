# How to Compile the Application into an Executable

This guide will walk you through the process of compiling the application into a standalone executable using PyInstaller.

## 1. Install PyInstaller

First, you need to install PyInstaller. You can do this using `pip`:

```bash
pip install pyinstaller
```

## 2. Compile the Application

Once PyInstaller is installed, you can compile the application by running the following command in your terminal from the root directory of the project:

```bash
pyinstaller --onefile --add-data "templates:templates" --add-data "static:static" main.py
```

Let's break down this command:

*   `--onefile`: This tells PyInstaller to create a single executable file.
*   `--add-data "templates:templates"`: This is crucial for web applications. It tells PyInstaller to include the `templates` directory in the compiled application. The format is `source:destination`.
*   `--add-data "static:static"`: Similarly, this includes the `static` directory, which contains your CSS, JavaScript, and other assets.
*   `main.py`: This is the entry point of your application.

After running this command, you will find a `dist` directory in your project. Inside this directory, you will find the compiled executable (e.g., `main.exe` on Windows or `main` on macOS/Linux).

## 3. Run the Executable

You can now run the application by executing the file from the `dist` directory:

```bash
./dist/main
```

Or on Windows:

```bash
dist\\main.exe
```

## 4. Using the `--output-yml` Argument

You can use the `--output-yml` argument that we added to specify a custom path for the `blackbox-targets.yml` file. For example:

```bash
./dist/main --output-yml /path/to/your/custom-targets.yml
```

Or on Windows:

```bash
dist\\main.exe --output-yml C:\\path\\to\\your\\custom-targets.yml
```

This will create the `custom-targets.yml` file in the specified directory. If you don't provide the `--output-yml` argument, it will default to creating `blackbox-targets.yml` in the same directory as the executable.
