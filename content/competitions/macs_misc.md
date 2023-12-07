---
toc: true
title: MACS Misc Challenges
description: MACS Misc Challenges
date: 2023-11-04
author: Duc Anh Nguyen
---


## 1. [Undroppable Table](../image/macs_misc/1699087185015.png)

We are given a [XLS file](https://github.com/heckintosh/CTF/blob/main/MACS/misc/undroppable_table/FLAG3.xlsx).

![1699102655605](../image/macs_misc/1699102655605.png)
*FLAG3.xls: Dwell on this a bit and you will realise that you need to place blue as 1, white as 0.*

Write some VBA code in excel to change all blue cells to 1 (gotta know its RGB color first). White cells as 0. Concat all in a row to form a byte. Convert that byte to character. Concat all characters in the column to get a sentence. In that sentence, there is the flag.

![1699103979952](../image/macs_misc/1699103979952.png)


## 2. [938574 cells and the flag is in some](../image/macs_misc/1699105562065.png)

There is a given [XLS file](https://github.com/heckintosh/CTF/blob/main/MACS/misc/938574/FLAG1.xlsx) which contains gibberish:
![1699105694980](../image/macs_misc/1699105694980.png)
*FLAG1.xls: Examing the cells, the characters are created randomly through =CHAR(RANDBETWEEN(34, 255)) or =CHAR(RANDBETWEEN(33, 255))*

Write VBA code to exclude all the cells that use the functions CHAR(RANDBETWEEN()) and we get all the characters that constitute the flag.

## 3. [Perspective](../image/macs_misc/1699107328310.png)

Zoom out the [XLS file](https://github.com/heckintosh/CTF/blob/main/MACS/misc/938574/FLAG1.xlsx) and there is a QR code to scan. Change the fill and font color a bit so the QR scanner picks it up easier.
![1699107291641](../image/macs_misc/1699107291641.png)

## 4. [Inspector Gadget](../image/macs_misc/1699109425382.png)
Zoom out, adjust width and height of the [XLS file](https://github.com/heckintosh/CTF/blob/main/MACS/misc/inspector_gadget/RobFlag2.xlsx) to reveal a QR code.
![1699108146578](../image/macs_misc/1699108146578.png)

After scanning the QR code we are directed to: https://robf101.bitbucket.io/mypage1.html
Turn on Burp Suite, inspect the respond to find that there is a code section which incorrectly shows only 2 of 4 pictures for a slideshow. Go to https://robf101.bitbucket.io/assets/BACScreen4.jpg to get the flag.


## 5. [discord over Discord](../image/macs_misc/1699937886295.png)

The bot is at: https://discord.gg/KmUVHCz7Hw


Use the command .typetest and the bot will give us a phrase, our task is to normalise the given unicode sentence and return the normalised sentence as fast as possible back to the bot to achieve 300 WPM.
![1699953783463](../image/macs_misc/1699953783463.png)

I just paste the sentence onto a webservice and paste back to the bot as fast as possible, no need to mess with discord API.

`MACS{1nt3nded_g4mepl4y_1s_f0r_n00bs}`


## 6. [Epic Terminal](../image/macs_misc/1700095808010.png)


## 7. [Enter The Matrix](../image/macs_misc/1700103805029.png)
We have to figure out the flag through this image only:

![Matrix](https://raw.githubusercontent.com/heckintosh/CTF/main/MACS/misc/enter_the_matrix/unknown.png)

It looks like a data matrix but it is not. The solution is to treat the background color as 0 and the foreground as 1. I edited the "matrix" a bit so it becomes black and white and easier to process. Remove the edge since that only serves as a red herring and makes the challenge seems like a data matrix.

![Matrix](https://raw.githubusercontent.com/heckintosh/CTF/main/MACS/misc/enter_the_matrix/unknown_edit.png)

```python
from PIL import Image

# Load the image
image = Image.open('unknown_edit.png')  # Replace with your image path
image = image.convert('L')  # Convert to grayscale

binary_string = ""

# Apply threshold to convert to strictly black and white
threshold_value = 90 # Adjust this threshold value if needed
image = image.point(lambda p: 0 if p < threshold_value else 255, '1')

pixel_block_size = 10

# Get the dimensions of the image
width, height = image.size

# Initialize an empty binary string
binary_string = ''

for y in range(0, height, pixel_block_size):
    for x in range(0, width, pixel_block_size):
        # Define the boundaries for the current block
        x_end = min(x + pixel_block_size, width)
        y_end = min(y + pixel_block_size, height)

        # Track the count of black pixels in the block
        black_pixel_count = 0

        # Count black pixels in the current block
        for j in range(y, y_end):
            for i in range(x, x_end):
                pixel_color = image.getpixel((i, j))
                if pixel_color == 0:
                    black_pixel_count += 1

        # Determine if the majority of pixels in the block are black
        if black_pixel_count > (pixel_block_size * pixel_block_size) / 2:
            binary_string += '0'  # Add '1' for majority black blocks
        else:
            binary_string += '1'  # Add '0' for majority white blocks

# Print or use the binary string
print("Binary String:", binary_string)
binary_values = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]

# Convert each 8-bit binary value to ASCII
ascii_chars = ''.join([chr(int(binary, 2)) for binary in binary_values])

print(ascii_chars)
```

## 8. [Redstone Reckoning](../image/macs_misc/1700274148173.png)

Quite intuitive, just download Minecraft, import the given maps and flip them switches on until the output is on.

![1700274237684](../image/macs_misc/1700274237684.png)

## 9. [Sudoku Challenge](../image/macs_misc/1700719659332.png)

Literally just solve sudoku, we can parse the sudoku puzzle into a list of list and feed it into the solver of `py-sudoku`:

```python
from pwn import *
from sudoku import Sudoku


def parse_sudoku(plain_text):
    result = []
    lines = plain_text.split("\n")
    while '' in lines:
        lines.remove('')
    for line in lines:
        res_line = []
        for num in line.split("|"):
            if num == " " * 3:
                res_line.append(0)
            elif num.strip().isdigit():
                num_ = int(num.strip())
                res_line.append(num_)
        result.append(res_line)
    return result

r = remote('chal2.macs.codes', 8385)
print(r.recvuntilS(":"))
r.sendline(b"6")

for i in range(0,10):
    if i != 0:
            print(r.recvuntilS(b":"))
    puzzle_str = r.recvuntilS(b"\n\n")
    puzzle_list = parse_sudoku(puzzle_str)
    puzzle = Sudoku(3,3, board=puzzle_list)
    solution = puzzle.solve().board
    solution = ''.join([str(item) for sublist in solution for item in sublist])
    r.sendline(solution)

print(r.recvall(timeout=4))
```

# 10. [Enter the Matrix 2](../image/macs_misc/1700804683119.png)

# 11. [Super MACS Bros]()
The game is made from Unity and I have never done Unity game development before. I choose to read about how to reverse Unity games through this [blog](https://jf.id.au/blog/reverse-engineering-a-unity-game). Use dnSpy to read the source code of class `KeyInput` and class `KeyValidator` inside `Assembly-CSharp.dll`:

```csharp
public class KeyInput : MonoBehaviour
{
	// Token: 0x0600002D RID: 45 RVA: 0x000028D7 File Offset: 0x00000AD7
	private void Start()
	{
		this.validator = base.GetComponent<KeyValidator>();
		this.statusText.enabled = false;
	}
...
public void SubmitKey()
	{
		this.statusText.enabled = false;
		this.statusText.color = Color.gray;
		string text = "";
		for (int i = 0; i < this.inputs.Length; i++)
		{
			text += this.inputs[i].text.ToUpper();
		}
		if (text.Length != 25)
		{
			this.statusText.text = "Please enter a complete 25-character key!";
			this.statusText.enabled = true;
			this.statusText.color = Color.red;
			return;
		}
		if (!this.validator.ValidateKey(text))
		{
			this.statusText.text = "Key format is not valid!";
			this.statusText.enabled = true;
			this.statusText.color = Color.red;
			return;
		}
		this.statusText.text = "Contacting key server...";
		this.statusText.enabled = true;
		base.StartCoroutine(this.validator.SubmitKey(text, delegate(bool success, string message)
		{
			if (success)
			{
				this.statusText.text = "Key validation successful!\nServer sent message: <b>" + message + "</b>";
				this.statusText.color = Color.green;
				return;
			}
			this.statusText.text = "Key validation failed!\nServer error: " + message;
			this.statusText.color = Color.red;
		}));
	}
...
}
```

```csharp
public bool ValidateKey(string key)
	{
		int num = 0;
		for (int i = 0; i < key.Length; i++)
		{
			num += (int)key[i];
		}
		return num == KeyValidator.KEYSUM;
	}

	// Token: 0x06000033 RID: 51 RVA: 0x00002B0E File Offset: 0x00000D0E
	public IEnumerator SubmitKey(string key, KeyValidator.OnServerResponse callback)
	{
		WWWForm wwwform = new WWWForm();
		wwwform.AddField("key", key);
		using (UnityWebRequest request = UnityWebRequest.Post(KeyValidator.SERVER, wwwform))
		{
			yield return request.SendWebRequest();
			if (request.result != UnityWebRequest.Result.Success)
			{
				callback(false, request.error);
			}
			else
			{
				KeyValidator.ServerResponse serverResponse = JsonUtility.FromJson<KeyValidator.ServerResponse>(request.downloadHandler.text);
				callback(serverResponse.success, serverResponse.message);
			}
		}
		UnityWebRequest request = null;
		yield break;
		yield break;
	}

	// Token: 0x04000035 RID: 53
	private static readonly int KEYSUM = 2050;

	// Token: 0x04000036 RID: 54
	private static readonly string SERVER = "https://flagserver.herokuapp.com/check-game-key";
```

Gotta bypass the ValidateKey function to actually capture the key sending request to the flagserver. A valid key has the key length of 25, contain only alphanumeric characters and has the sum of 2050 for all of the key characters after being turn into uppercase. One such key would be `print("R"*25)` since the ASCII value of R is 82. After using the key, the following request is sent to the key server by the game (gotta setup proxy and catch the request to key server through Burp Suite):

```http
POST /check-game-key HTTP/1.1
Host: flagserver.herokuapp.com
User-Agent: UnityPlayer/2020.2.0f1 (UnityWebRequest/1.0, libcurl/7.52.0-DEV)
Accept: */*
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
X-Unity-Version: 2020.2.0f1
Content-Length: 29
Connection: close

key=RRRRRRRRRRRRRRRRRRRRRRRRR
```

Response:
```http
HTTP/1.1 404 Not Found
Content-Length: 563
Cache-Control: no-cache, no-store
Content-Type: text/html; charset=utf-8
Date: 2023-11-27 23:19:02.471065714 +0000 UTC
Server: heroku-router
```

We have to manipulate the JSON response from the server so that it satisfies the `SubmitKey` function which means the JSON response has to contain two field: `success` and `message`. `success` should be true. But ..., even after the response manipulation succeeds, there is actually no content after the level so basically I waste a bunch of time doing this.

![1701129426015](../image/macs_misc/1701129426015.png)
<p style="text-align: center;"><i>The game stucks here and would not let me proceed to level 2</i></p>

Have to change my approach and try to [extract the assets](https://github.com/imadr/Unity-game-hacking).