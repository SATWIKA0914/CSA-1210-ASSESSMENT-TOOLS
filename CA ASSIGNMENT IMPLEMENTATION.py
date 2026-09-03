import tkinter as tk
from tkinter import messagebox


# ---------- BASE CLASS ----------
class Analyzer:
    def __init__(self, job_id, images, image_size, clock):
        self.job_id = job_id
        self.images = images
        self.image_size = image_size
        self.clock = clock

    def analyze(self):
        return "Base Analyzer"


# ---------- PIPELINE ----------
class PipelineAnalyzer(Analyzer):
    def __init__(self, job_id, images, image_size, clock, instructions):
        super().__init__(job_id, images, image_size, clock)
        self.instructions = instructions
        self.rows = []
        self.data_hazards = []
        self.control_hazards = []
        self.structural_hazards = []
        self.stalls = 0
        self.flushes = 0

    def analyze(self):
        current_if = 1

        for i, ins in enumerate(self.instructions):

            stall = 0

            # Data hazard
            if i > 0:
                for old in self.instructions[max(0, i - 2):i]:
                    if old["dest"] != "-" and old["dest"] in ins["src"]:
                        stall = 1
                        self.data_hazards.append(
                            ins["id"] + " depends on " + old["id"]
                        )
                        break

            current_if += stall

            IF = current_if
            ID = IF + 1
            EX = ID + 1
            MEM = EX + 1
            WB = MEM + 1

            # Control hazard
            if ins["op"] == "BRANCH":
                self.control_hazards.append(ins["id"])
                self.flushes += 2

            # Structural hazard
            if i > 0 and ins["op"] in ["LOAD", "STORE"]:
                previous = self.rows[-1]

                if previous["IF"] + 1 == MEM:
                    self.structural_hazards.append(ins["id"])
                    stall = max(stall, 1)

            self.stalls += stall

            self.rows.append({
                "id": ins["id"],
                "op": ins["op"],
                "IF": IF,
                "ID": ID,
                "EX": EX,
                "MEM": MEM,
                "WB": WB
            })

            current_if = IF + 1

            if ins["op"] == "BRANCH":
                current_if += 2

        if self.rows:
            cycles = max(x["WB"] for x in self.rows) + self.flushes
        else:
            cycles = 0

        n = len(self.instructions)

        if n > 0:
            cpi = cycles / n
            speedup = (5 * n) / cycles
        else:
            cpi = 0
            speedup = 0

        execution_time = cycles * self.clock

        return {
            "cycles": cycles,
            "cpi": cpi,
            "speedup": speedup,
            "execution_time": execution_time
        }


# ---------- CACHE ----------
class CacheAnalyzer:

    def __init__(self, addresses):
        self.addresses = addresses

        self.levels = [
            {
                "name": "L1",
                "size": 1024,
                "block": 16,
                "latency": 1
            },
            {
                "name": "L2",
                "size": 4096,
                "block": 16,
                "latency": 4
            },
            {
                "name": "L3",
                "size": 16384,
                "block": 16,
                "latency": 12
            }
        ]

    def simulate(self, addresses, size, block):

        sets = max(1, size // block)

        cache = [None] * sets

        hits = 0
        misses = 0

        for address in addresses:

            block_no = address // block
            index = block_no % sets
            tag = block_no // sets

            if cache[index] == tag:
                hits += 1
            else:
                misses += 1
                cache[index] = tag

        return hits, misses

    def analyze(self):

        result = []

        remaining = self.addresses[:]

        for level in self.levels:

            hits, misses = self.simulate(
                remaining,
                level["size"],
                level["block"]
            )

            total = hits + misses

            if total > 0:
                hit_ratio = hits / total
                miss_ratio = misses / total
            else:
                hit_ratio = 0
                miss_ratio = 0

            result.append({
                "name": level["name"],
                "hits": hits,
                "misses": misses,
                "hit_ratio": hit_ratio,
                "miss_ratio": miss_ratio,
                "latency": level["latency"]
            })

            remaining = remaining[:misses]

        if self.addresses:

            l1 = result[0]
            l2 = result[1]
            l3 = result[2]

            memory_latency = 100

            amat = (
                l1["latency"]
                + l1["miss_ratio"] *
                (
                    l2["latency"]
                    + l2["miss_ratio"] *
                    (
                        l3["latency"]
                        + l3["miss_ratio"] *
                        memory_latency
                    )
                )
            )

        else:
            amat = 0

        return result, amat


# ---------- I/O ----------
class IOAnalyzer:

    def __init__(self, images, image_size, rate, requests):
        self.images = images
        self.image_size = image_size
        self.rate = rate
        self.requests = requests

    def analyze(self):

        total_data = self.images * self.image_size

        if self.rate > 0:
            transfer_time = total_data / self.rate
        else:
            transfer_time = 0

        interrupt_time = (
            transfer_time +
            self.requests * 0.002
        )

        dma_time = (
            transfer_time +
            self.requests * 0.0005
        )

        interrupt_cpu = min(
            100,
            self.requests * 2
        )

        dma_cpu = min(
            100,
            self.requests * 0.2
        )

        return {
            "data": total_data,
            "interrupt_time": interrupt_time,
            "dma_time": dma_time,
            "interrupt_interventions": self.requests,
            "dma_interventions": 1,
            "interrupt_cpu": interrupt_cpu,
            "dma_cpu": dma_cpu
        }


# ---------- INSTRUCTION INPUT ----------
def parse_instructions(text):

    instructions = []

    lines = text.strip().splitlines()

    for line in lines:

        if not line.strip():
            continue

        parts = [
            x.strip()
            for x in line.split(",")
        ]

        if len(parts) != 5:

            raise ValueError(
                "Instruction format:\n"
                "ID,OPERATION,SOURCE,DESTINATION,ADDRESS"
            )

        iid = parts[0]
        op = parts[1].upper()
        src = parts[2]
        dest = parts[3]
        address = parts[4]

        valid_operations = [
            "ADD",
            "SUB",
            "MUL",
            "LOAD",
            "STORE",
            "BRANCH"
        ]

        if op not in valid_operations:
            raise ValueError(
                "Invalid operation: " + op
            )

        if src == "-":
            source = []
        else:
            source = [
                x.strip()
                for x in src.split(";")
            ]

        if address == "-":
            addr = None
        else:
            addr = int(address)

        instructions.append({
            "id": iid,
            "op": op,
            "src": source,
            "dest": dest,
            "address": addr
        })

    return instructions


# ---------- REPORT ----------
def create_report(
    pipeline,
    cache,
    amat,
    io,
    job_id
):

    report = ""

    report += "AI WORKLOAD PERFORMANCE ANALYZER\n"
    report += "=================================\n"
    report += "Job ID: " + job_id + "\n\n"

    # Pipeline
    report += "1. PIPELINE ANALYSIS\n"
    report += "--------------------\n"

    report += (
        "ID\tOP\tIF\tID\tEX\tMEM\tWB\n"
    )

    for row in pipeline["rows"]:

        report += (
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\n"
        ).format(
            row["id"],
            row["op"],
            row["IF"],
            row["ID"],
            row["EX"],
            row["MEM"],
            row["WB"]
        )

    report += "\n"

    report += "Data Hazards: "
    report += str(
        pipeline["data_hazards"]
        if pipeline["data_hazards"]
        else "None"
    )
    report += "\n"

    report += "Control Hazards: "
    report += str(
        pipeline["control_hazards"]
        if pipeline["control_hazards"]
        else "None"
    )
    report += "\n"

    report += "Structural Hazards: "
    report += str(
        pipeline["structural_hazards"]
        if pipeline["structural_hazards"]
        else "None"
    )
    report += "\n"

    report += "Stall Cycles: "
    report += str(pipeline["stalls"])
    report += "\n"

    report += "Flush Cycles: "
    report += str(pipeline["flushes"])
    report += "\n"

    report += "Total Pipeline Cycles: "
    report += str(pipeline["cycles"])
    report += "\n"

    report += "CPI: {:.2f}\n".format(
        pipeline["cpi"]
    )

    report += "Pipeline Speed-up: {:.2f}\n".format(
        pipeline["speedup"]
    )

    report += "Execution Time: {:.2f} ns\n\n".format(
        pipeline["execution_time"]
    )

    # Cache
    report += "2. CACHE ANALYSIS\n"
    report += "-----------------\n"

    for c in cache:

        report += (
            "{}: Hits={}, Misses={}, "
            "Hit Ratio={:.2f}, Miss Ratio={:.2f}, "
            "Latency={} ns\n"
        ).format(
            c["name"],
            c["hits"],
            c["misses"],
            c["hit_ratio"],
            c["miss_ratio"],
            c["latency"]
        )

    report += (
        "Average Memory Access Time: {:.2f} ns\n\n"
    ).format(amat)

    # I/O
    report += "3. I/O AND DMA ANALYSIS\n"
    report += "-----------------------\n"

    report += "Total Data: {:.2f} MB\n".format(
        io["data"]
    )

    report += (
        "Interrupt I/O Transfer Time: {:.4f} s\n"
    ).format(
        io["interrupt_time"]
    )

    report += (
        "DMA Transfer Time: {:.4f} s\n"
    ).format(
        io["dma_time"]
    )

    report += (
        "Interrupt CPU Interventions: {}\n"
    ).format(
        io["interrupt_interventions"]
    )

    report += (
        "DMA CPU Interventions: {}\n"
    ).format(
        io["dma_interventions"]
    )

    report += (
        "Interrupt CPU Utilization: {:.2f}%\n"
    ).format(
        io["interrupt_cpu"]
    )

    report += (
        "DMA CPU Utilization: {:.2f}%\n\n"
    ).format(
        io["dma_cpu"]
    )

    # Final
    report += "4. FINAL PERFORMANCE REPORT\n"
    report += "---------------------------\n"

    if io["interrupt_time"] > pipeline["execution_time"] / 1000000000:
        bottleneck = "I/O"
    elif amat > 10:
        bottleneck = "Cache"
    else:
        bottleneck = "Pipeline"

    report += "Major Bottleneck: "
    report += bottleneck
    report += "\n\n"

    report += "Recommendation:\n"
    report += (
        "Reduce pipeline hazards, improve cache locality "
        "and use DMA for efficient data transfer.\n"
    )

    return report


# ---------- RUN ----------
def run_analysis():

    try:

        job_id = job_entry.get().strip()

        images = int(
            images_entry.get()
        )

        image_size = float(
            size_entry.get()
        )

        clock = float(
            clock_entry.get()
        )

        rate = float(
            rate_entry.get()
        )

        requests = int(
            request_entry.get()
        )

        if job_id == "":
            raise ValueError(
                "Enter Job ID."
            )

        if images <= 0:
            raise ValueError(
                "Images must be greater than 0."
            )

        if image_size <= 0:
            raise ValueError(
                "Image size must be greater than 0."
            )

        if clock <= 0:
            raise ValueError(
                "Clock time must be greater than 0."
            )

        if rate <= 0:
            raise ValueError(
                "Transfer rate must be greater than 0."
            )

        instructions = parse_instructions(
            instruction_box.get(
                "1.0",
                tk.END
            )
        )

        if len(instructions) == 0:
            raise ValueError(
                "Enter instructions."
            )

        # Pipeline
        pipeline_obj = PipelineAnalyzer(
            job_id,
            images,
            image_size,
            clock,
            instructions
        )

        pipeline_result = pipeline_obj.analyze()

        # Cache
        addresses = []

        for ins in instructions:

            if (
                ins["op"] == "LOAD"
                or ins["op"] == "STORE"
            ):

                if ins["address"] is not None:
                    addresses.append(
                        ins["address"]
                    )

        cache_obj = CacheAnalyzer(
            addresses
        )

        cache_result, amat = (
            cache_obj.analyze()
        )

        # I/O
        io_obj = IOAnalyzer(
            images,
            image_size,
            rate,
            requests
        )

        io_result = io_obj.analyze()

        # Report
        pipeline_data = {
            **pipeline_result,
            "rows": pipeline_obj.rows,
            "data_hazards":
                pipeline_obj.data_hazards,
            "control_hazards":
                pipeline_obj.control_hazards,
            "structural_hazards":
                pipeline_obj.structural_hazards,
            "stalls":
                pipeline_obj.stalls,
            "flushes":
                pipeline_obj.flushes
        }

        report = create_report(
            pipeline_data,
            cache_result,
            amat,
            io_result,
            job_id
        )

        output_box.delete(
            "1.0",
            tk.END
        )

        output_box.insert(
            tk.END,
            report
        )

        # File handling
        with open(
            "AI_Workload_Report.txt",
            "w"
        ) as file:

            file.write(report)

        messagebox.showinfo(
            "Success",
            "Analysis completed!\n\n"
            "Report saved as:\n"
            "AI_Workload_Report.txt"
        )

    except ValueError as error:

        messagebox.showerror(
            "Input Error",
            str(error)
        )

    except Exception as error:

        messagebox.showerror(
            "Error",
            str(error)
        )


# ---------- SAMPLE DATA ----------
def load_sample():

    job_entry.delete(
        0,
        tk.END
    )

    job_entry.insert(
        0,
        "AI001"
    )

    images_entry.delete(
        0,
        tk.END
    )

    images_entry.insert(
        0,
        "100"
    )

    size_entry.delete(
        0,
        tk.END
    )

    size_entry.insert(
        0,
        "2"
    )

    clock_entry.delete(
        0,
        tk.END
    )

    clock_entry.insert(
        0,
        "1"
    )

    rate_entry.delete(
        0,
        tk.END
    )

    rate_entry.insert(
        0,
        "500"
    )

    request_entry.delete(
        0,
        tk.END
    )

    request_entry.insert(
        0,
        "20"
    )

    instruction_box.delete(
        "1.0",
        tk.END
    )

    sample = (
        "I1,LOAD,-,R1,100\n"
        "I2,ADD,R1,R2,-\n"
        "I3,SUB,R2,R3,-\n"
        "I4,STORE,R3,-,116\n"
        "I5,BRANCH,R3,-,-\n"
        "I6,LOAD,-,R4,132"
    )

    instruction_box.insert(
        tk.END,
        sample
    )


# ---------- GUI ----------
root = tk.Tk()

root.title(
    "AI Workload Performance Analyzer"
)

root.geometry(
    "1100x750"
)

title = tk.Label(
    root,
    text="AI WORKLOAD PERFORMANCE ANALYZER",
    font=("Arial", 18, "bold")
)

title.pack(
    pady=10
)


# Input frame
frame = tk.Frame(root)

frame.pack()


tk.Label(
    frame,
    text="Job ID"
).grid(
    row=0,
    column=0,
    padx=5,
    pady=5
)

job_entry = tk.Entry(
    frame,
    width=12
)

job_entry.grid(
    row=0,
    column=1
)


tk.Label(
    frame,
    text="Images"
).grid(
    row=0,
    column=2
)

images_entry = tk.Entry(
    frame,
    width=10
)

images_entry.grid(
    row=0,
    column=3
)


tk.Label(
    frame,
    text="Image Size (MB)"
).grid(
    row=0,
    column=4
)

size_entry = tk.Entry(
    frame,
    width=10
)

size_entry.grid(
    row=0,
    column=5
)


tk.Label(
    frame,
    text="Clock (ns)"
).grid(
    row=1,
    column=0,
    padx=5,
    pady=5
)

clock_entry = tk.Entry(
    frame,
    width=10
)

clock_entry.grid(
    row=1,
    column=1
)


tk.Label(
    frame,
    text="Storage Rate (MB/s)"
).grid(
    row=1,
    column=2
)

rate_entry = tk.Entry(
    frame,
    width=10
)

rate_entry.grid(
    row=1,
    column=3
)


tk.Label(
    frame,
    text="Transfer Requests"
).grid(
    row=1,
    column=4
)

request_entry = tk.Entry(
    frame,
    width=10
)

request_entry.grid(
    row=1,
    column=5
)


tk.Label(
    root,
    text=(
        "Instruction Format: "
        "ID,OPERATION,SOURCE,DESTINATION,ADDRESS"
    ),
    font=("Arial", 10, "bold")
).pack(
    pady=5
)


instruction_box = tk.Text(
    root,
    height=9,
    width=105
)

instruction_box.pack()


# Buttons
button_frame = tk.Frame(root)

button_frame.pack(
    pady=10
)


tk.Button(
    button_frame,
    text="Load Sample",
    command=load_sample,
    width=15
).grid(
    row=0,
    column=0,
    padx=10
)


tk.Button(
    button_frame,
    text="Run Analysis",
    command=run_analysis,
    width=15
).grid(
    row=0,
    column=1,
    padx=10
)


tk.Label(
    root,
    text="FINAL PERFORMANCE REPORT",
    font=("Arial", 13, "bold")
).pack()


output_box = tk.Text(
    root,
    height=25,
    width=125
)

output_box.pack(
    padx=10,
    pady=5
)


# Load sample automatically
load_sample()

root.mainloop()
