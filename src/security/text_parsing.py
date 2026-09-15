"""Linear scans for delimiter-based model output parsing."""

def extract_tag_blocks(text: str, tag: str, *, ignore_case: bool = False):
    source = text.lower() if ignore_case else text
    opening, closing = '<' + tag + '>', '</' + tag + '>'
    blocks, output = [], []
    cursor = 0
    while True:
        start = source.find(opening, cursor)
        if start < 0:
            output.append(text[cursor:])
            break
        end = source.find(closing, start + len(opening))
        if end < 0:
            output.append(text[cursor:])
            break
        output.append(text[cursor:start])
        blocks.append(text[start + len(opening):end])
        cursor = end + len(closing)
    return blocks, ''.join(output)
