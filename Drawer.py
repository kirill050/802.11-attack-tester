from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.progress import Progress
from rich.text import Text
from rich import print
from rich.panel import Panel


class drawer:
    def __init__(self):
        self.Title = '''802.11 attack tester\nby Tikhonov K. & Dement`ev S.\n'''
        self.console = Console()

    def draw_table(self, columns, rows, subtitle=""):
        table = Table(title=self.Title+subtitle)
        for name in columns:
            table.add_column(name, style="green")
        for row in rows:
            try:
                table.add_row(*row)
            except:
                continue
        self.console.print(table)

    def draw_progress(self, description, target_count):
        self.progress = Progress()
        task = self.progress.add_task(description, total=target_count)
        return task
        # with Progress() as self.progress:
        #     task = self.progress.add_task(description, total=target_count)
        #     return task

    def update_progress(self, task_id, count=1):
        self.progress.update(task_id, advance=count)

    def print_text(self, text, style: str = "", align: str = ""):
        self.console.print(Text(text, style=style, justify=align, no_wrap=True))

    def print_label(self):
        panel = Panel(Text(self.Title, justify="center"))
        print(panel)
        # self.print_text(self.Title, align="right")

    def get_input(self, question, var_type=int):
        res = self.console.input(question)
        try:
            res = var_type(res)
            return res
        except:
            if "q" in res:
                return -1
            print(f"You should enter value of type{var_type}!!!")
            return self.get_input(question, var_type)

    def clean(self):
        self.console.clear()

