<!-- PROJECT LOGO -->
<p align="center">
  <h3 align="center">python-inject</h3>

  <p align="center">
    Inject code into remote python process.
    <br />
    <br />
    <a href="https://github.com/bytedance/Elkeid/issues">Report Bug</a>
    ·
    <a href="https://github.com/bytedance/Elkeid/issues">Request Feature</a>
  </p>
</p>



<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgements">Acknowledgements</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

Resolve ELF symbol table, find ```PyGILState_Ensure```, ```PyRun_SimpleString``` and ```PyGILState_Release``` function address, then call them in remote process by using ptrace.

### Built With

* [GCC](https://gcc.gnu.org)
* [Make](https://www.gnu.org/software/make)
* [CMake](https://cmake.org)



<!-- GETTING STARTED -->
## Getting Started

### Prerequisites

* CMake
  ```sh
  curl https://github.com/Kitware/CMake/releases/download/v3.21.0/cmake-3.21.0-linux-x86_64.sh | sh
  ```

### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/bytedance/Elkeid.git
   ```
2. Update submodule
   ```sh
   git submodule update --init --recursive
   ```
3. Build shellcode
   ```sh
   make -C shellcode
   ```
4. Build injector
   ```sh
   mkdir -p build && cd build && cmake .. && make
   ```



<!-- USAGE EXAMPLES -->
## Usage

```sh
usage: python_inject [options] pid(int) script(string) ... extra ...
positional:
	pid                 process id(int)
	script              python script(string)
optional:
	-?, --help          print help message
	-f, --file          eval script from file
```

Inject script:
```sh
./python_inject $(pidof python) "print('hello world')"
```



<!-- ROADMAP -->
## Roadmap

See the [open issues](https://github.com/bytedance/Elkeid/issues) for a list of proposed features (and known issues).



<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request



<!-- LICENSE -->
## License

Distributed under the Apache-2.0 License.



<!-- CONTACT -->
## Contact

Bytedance - [@bytedance](https://github.com/bytedance)

Project Link: [https://github.com/bytedance/Elkeid](https://github.com/bytedance/Elkeid)



<!-- ACKNOWLEDGEMENTS -->
## Acknowledgements
* [ELFIO](https://github.com/serge1/ELFIO)