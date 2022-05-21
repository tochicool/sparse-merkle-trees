# Contributing

## Building from source

### Prerequisites

This guide assumes you have install the following development tools for your operating
system:

- [git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)
- [stack](https://docs.haskellstack.org/en/stable/install_and_upgrade/)

```bash
git clone https://github.com/tochicool/sparse-merkle-trees
cd sparse-merkle-trees
```

### Building the library

```bash
stack build
```

### Running the unit tests

```bash
stack test
```

### Running the benchmarks

```bash
stack bench --ba "--output benchmarks.html"
```

Open `benchmarks.html` in your browser for the rendered results.


## Cod
