# CTF Writeup: Recovering Data from Binary Strings (`digits.bin`)

## Challenge Details
- **Category:** Forensics / Data Recovery / Encoding
- **File Provided:** `digits.bin`
- **Tool Used:** [CyberChef](https://gchq.github.io/CyberChef/)

---

## 1. Challenge Analysis

When opening `digits.bin`, we observe a continuous stream of ASCII characters consisting entirely of `1`s and `0`s:

```text
111111111101100011111111111000000000000000010000...
```

Instead of true binary bytes, the file stores literal textual representations of bits. Since all computer files are ultimately sequences of bytes (where 1 byte = 8 bits), we can analyze the first few groups of 8 bits to check for recognizable file headers (**magic numbers**).

### Inspecting the Magic Bytes

Splitting the first 32 bits into 8-bit octets:

| Binary Octet | Decimal | Hexadecimal |
| :--- | :--- | :--- |
| `11111111` | 255 | `0xFF` |
| `11011000` | 216 | `0xD8` |
| `11111111` | 255 | `0xFF` |
| `11100000` | 224 | `0xE0` |

- **Header Signature:** `FF D8 FF E0` corresponds directly to the start of a **JPEG / JFIF** image file.
- **Trailer Signature:** Checking the final 16 bits of the string (`1111111111011001`) yields `FF D9`, which is the standard JPEG **EOI (End of Image)** marker.

This confirms that the stream of `1`s and `0`s represents a complete, valid JPEG file.

---

## 2. Step-by-Step Solution via CyberChef

### Step 1: Supply the Input
1. Open [CyberChef](https://gchq.github.io/CyberChef/).
2. Copy the entire contents of `digits.bin` and paste it into the **Input** pane on the top right.

### Step 2: Set Up the Conversion Recipe
1. In the search box under **Operations** (left pane), search for `From Binary`.
2. Drag `From Binary` into the central **Recipe** area.
3. Configure the operation settings:
   - **Byte length:** `8` (each character group of 8 bits represents 1 byte)
   - **Delimiter:** `None` (there are no spaces or commas between the bits)

### Step 3: Extract / View the Image
Once the `From Binary` operation processes the data, you can obtain the image in either of two ways:

- **Method A (Direct Download):** Click the **Save output to file** icon (floppy disk icon above the Output pane) and save the file as `flag.jpg`.
- **Method B (Preview in Browser):** Add the `Render Image` operation to your recipe chain and set the format to `JPEG/JPG` to inspect the flag directly inside CyberChef.

---

## 3. Flag Extraction

Opening `flag.jpg` reveals the rendered image containing the CTF flag.