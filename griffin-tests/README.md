# Griffin Trace Tests

## Usage

To run the Griffin tests, you'll run the bash scripts that automate the test process. Some programs are not specified exactly by location (gcc, dmesg, sleep), but should work as long as all these programs are accessible to the current user.

### Run the tests

```
sudo bash shadow-stack.sh
sudo bash forward-edge.sh
```


### Annotate the PT output

```
sudo bash annotate-shadow-stack.sh
sudo bash annotate-forward-edge.sh
```


## Output

### "dmesg" output for shadow stack tests

Output without API calls:

```
[329845.041684] pt: offline: attack-return.out registered
[329845.058259] pt: Adding buffer for #0, size (40)
[329845.063031] pt: Adding buffer for #1, size (944)
[329845.071575] pt: Adding buffer for #2, size (40)
[329845.076401] pt: Adding buffer for #3, size (4224)
[329845.084119] pt: [pid:6276] failed: unmatched return: 400546
[329845.106993] pt: offline:  registered
```

Output with system call trigger:

```
[329848.107256] pt: offline: attack-return.out registered
[329848.112988] pt: tracing system calls: 1 -> 1
[329848.117452] pt: tracing system calls: 1 -> 1
[329848.138097] pt:   System call captured. Will print to log.
[329848.143911] pt: Adding buffer for #4, size (40)
[329848.148668] pt: Adding buffer for #5, size (944)
[329848.155557] pt:   Dumping trace from syscall trigger. Called on 4, dumped on 0, width is 1.
[329848.164002] pt: Current buffer is #0, size (40)
[329848.168893] pt: Printing buffer #4 to 0, size (40)
[329848.173929] pt: Printing buffer #5 to 0, size (944)
[329848.178999] pt: Adding buffer for #0, size (40)
[329848.183685] pt: Adding buffer for #1, size (4208)
[329848.191346] pt: [pid:6281] failed: unmatched return: 400546
[329848.224407] pt: offline:  registered
```

Output with shadow stack trigger:

```
[329851.224733] pt: offline: attack-return.out registered
[329851.230333] pt: tracing shadow stack CFI violations: 2 -> 2
[329851.256252] pt: Adding buffer for #2, size (40)
[329851.260925] pt: Adding buffer for #3, size (944)
[329851.270639] pt: Adding buffer for #4, size (40)
[329851.275372] pt: Adding buffer for #5, size (4224)
[329851.283123] pt: [pid:6286] failed: unmatched return: 400546
[329851.288866] pt:   Dumping trace from CFI shadow stack trigger.
[329851.294722] pt: Current buffer is #0, size (40)
[329851.299607] pt: Printing buffer #4 to 0, size (40)
[329851.303994] pt: offline:  registered
```

Output with forward edge trigger:

```
[329851.308371] pt: Printing buffer #5 to 0, size (4224)
[329854.300266] pt: offline: attack-return.out registered
[329854.305848] pt: tracing fwd edge CFI violations: 2 -> 2
[329854.325921] pt: Adding buffer for #0, size (40)
[329854.330656] pt: Adding buffer for #1, size (944)
[329854.338712] pt: Adding buffer for #2, size (40)
[329854.343408] pt: Adding buffer for #3, size (4224)
[329854.351142] pt: [pid:6291] failed: unmatched return: 400546
[329854.359196] pt: offline:  registered
```

### Annotated output for shadow stack tests

```
tbd
```


### "dmesg" output for forward edge tests

Output without API calls:

```
[329895.923658] pt: offline: attack-call.out registered
[329895.942938] pt: Adding buffer for #4, size (40)
[329895.947671] pt: Adding buffer for #5, size (768)
[329895.974062] pt: Adding buffer for #0, size (40)
[329895.978749] pt: Adding buffer for #1, size (656)
[329895.984753] pt: Adding buffer for #2, size (40)
[329895.989403] pt: Adding buffer for #3, size (7840)
[329895.998023] pt: forward-edge violation: 0 -> 65535 (40051b)
[329896.007038] pt: offline:  registered
```

Output with system call trigger:

```
[329899.006887] pt: offline: attack-call.out registered
[329899.012561] pt: tracing system calls: 1 -> 1
[329899.017245] pt: tracing system calls: 1 -> 1
[329899.029466] pt:   System call captured. Will print to log.
[329899.035223] pt: Adding buffer for #4, size (40)
[329899.039929] pt: Adding buffer for #5, size (784)
[329899.047254] pt:   Dumping trace from syscall trigger. Called on 4, dumped on 0, width is 1.
[329899.055721] pt: Current buffer is #0, size (40)
[329899.060635] pt: Printing buffer #4 to 0, size (40)
[329899.065626] pt: Printing buffer #5 to 0, size (784)
[329899.070822] pt:   System call captured. Will print to log.
[329899.076504] pt: Adding buffer for #0, size (40)
[329899.081194] pt: Adding buffer for #1, size (656)
[329899.086849] pt: Adding buffer for #2, size (40)
[329899.091552] pt: Adding buffer for #3, size (7840)
[329899.100194] pt: forward-edge violation: 0 -> 65535 (40051b)
[329899.119556] pt: offline:  registered
```

Output with shadow stack trigger:

```
[329902.119664] pt: offline: attack-call.out registered
[329902.125152] pt: tracing shadow stack CFI violations: 2 -> 2
[329902.138969] pt: Adding buffer for #4, size (40)
[329902.143707] pt: Adding buffer for #5, size (768)
[329902.171986] pt: Adding buffer for #0, size (40)
[329902.176720] pt: Adding buffer for #1, size (624)
[329902.182880] pt: Adding buffer for #2, size (40)
[329902.187571] pt: Adding buffer for #3, size (7840)
[329902.196224] pt: forward-edge violation: 0 -> 65535 (40051b)
[329902.205513] pt: offline:  registered
```

Output with forward edge trigger:

```
[329905.205371] pt: offline: attack-call.out registered
[329905.211037] pt: tracing fwd edge CFI violations: 2 -> 2
[329905.229170] pt: Adding buffer for #4, size (40)
[329905.233903] pt: Adding buffer for #5, size (768)
[329905.256234] pt: Adding buffer for #0, size (40)
[329905.260874] pt: Adding buffer for #1, size (624)
[329905.266735] pt: Adding buffer for #2, size (40)
[329905.271436] pt: Adding buffer for #3, size (7840)
[329905.280198] pt: forward-edge violation: 0 -> 65535 (40051b)
[329905.286563] pt:   Dumping trace from CFI forward edge trigger.
[329905.292429] pt: Current buffer is #4, size (40)
[329905.297376] pt: Printing buffer #2 to 4, size (40)
[329905.302347] pt: Printing buffer #3 to 4, size (7840)
[329905.305092] pt: offline:  registered
```

### Annotated output for forward edge tests

```
tbd
```