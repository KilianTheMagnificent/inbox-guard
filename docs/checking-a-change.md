# How to check an AI-built change without reading the code

Suppose an assistant says it fixed a CSV export. Ask which cells should change. Pick one nearby value that would be expensive to get wrong, such as a refund, and write down what it should say afterward. You now have two things you can check yourself.

## Try it with four invented invoices

You need Git and Node.js 20 or newer. To get the [sample export](../examples/invoices.csv) and the tool, open a terminal and run these commands. If you already have a copy, open its folder. All four invoices contain invented data.

```sh
git clone https://github.com/KilianTheMagnificent/inbox-guard.git
cd inbox-guard
```

**1. Predict the result.** Open the sample in a text editor. The header counts as row 1. The memos for INV-002 and INV-004 start with arithmetic expressions. Those two cells should get a leading apostrophe. The refund of `-42.50` should keep its minus sign. The delivery note spans two lines inside one cell.

**2. Run the check.**

```sh
node ./bin/inbox-guard.mjs check-csv examples/invoices.csv
```

Look for five rows, four columns, and exactly two findings, both in column 4, at rows 3 and 5. The tool gives this result exit code 2. That means it found cells to review. A malformed file gets exit code 1 and an error message instead.

**3. Make a copy and inspect it.**

```sh
node ./bin/inbox-guard.mjs sanitize-csv examples/invoices.csv --output reviewed-invoices.csv
cat reviewed-invoices.csv
node ./bin/inbox-guard.mjs check-csv reviewed-invoices.csv
```

Find `INV-002` in the output. Its last cell now reads `"'=2+3"`. Find `INV-004` and look for `"'+2+3"`. Check the refund, the comma in the first vendor's name, and the line break inside the delivery note. The second check should still report five rows and four columns, with an empty findings list. Comparing the values yourself catches a tool that produces an empty findings list by dropping data.

**4. Test the promise that your original survives.** Run the copy command again with the same output filename. It should say `Output already exists`. Check the original with the first command. It should still report the same two cells. To try the exercise again, choose a fresh output name.

This exercise checks the CSV that the tool writes. If your decision depends on a particular spreadsheet app, use its import dialog with UTF-8 and a comma delimiter. Record the app and version and inspect the imported cells there before claiming that behavior.

## Keep a record someone else can repeat

Copy this short worksheet for the next change. Write the expected result before the assistant runs the check. Save only invented sample data in a public record.

| Write down | Example from this exercise |
| --- | --- |
| Version and environment | Copy the results of `git rev-parse --short HEAD` and `node --version`. |
| Input and action | Four sample invoices. Screen the sample, make a copy, inspect it, and screen the copy. |
| What should change | The memo in rows 3 and 5 gets a leading apostrophe. |
| What should survive | The refund, vendor with a comma, multiline delivery note, all four invoices and the original file. |
| What happened | Paste the observed coordinates and both memo values after running the commands. |
| What still needs checking | Name any spreadsheet app or import setting your users depend on. |
| Who checked | Name the person or tool that ran it. Mark a personal check only after doing it yourself. |

If the observed result differs, keep the smallest invented example that shows it. Give the assistant that input, the command you used, and the single value that differed. Use the same example to check the repair.
