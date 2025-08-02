import flet as ft
from ui.main_view import MainView
from state import AppState
from encryption_manager import EncryptionManager


async def main(page: ft.Page):
    """
    Main function of the application
    """
    # Page setup
    page.window.left = 400
    page.window.top = 200

    page.window.width = 525
    page.window.height = 600

    page.title = "Apata"
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = "#0f0f0f"
    page.padding = 20
    page.fonts = {"Roboto": "https://fonts.googleapis.com/css2?family=Roboto"}

    page.update()

    # Initialize state and encryption
    state = AppState()
    encryption_manager = EncryptionManager()

    # Create the main view
    main_view = MainView(page, state, encryption_manager)
    await main_view.setup_ui()


if __name__ == "__main__":
    ft.app(target=main)