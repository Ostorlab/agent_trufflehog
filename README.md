<h1 align="center">Agent Trufflehog</h1>



_TruffleHog is a fast secret scanner._

---


This repository is an implementation of [OXO Agent](https://pypi.org/project/ostorlab/) for the [TruffleHog Scanner](https://github.com/trufflesecurity/trufflehog) by Truffle security.

## Getting Started
To perform your first scan, simply run the following command:
```shell
oxo scan run --install --agent agent/ostorlab/trufflehog file [YOUR_TARGET_FILE]
```

This command will download and install `agent/ostorlab/trufflehog` and scan upir target file for secrets.
For more information, please refer to the [OXO Documentation](https://oxo.ostorlab.co/docs)


## Usage

Agent TruffleHog can be installed directly from the oxo agent store or built from this repository.

 ### Install directly from oxo agent store

 ```shell
 oxo agent install agent/ostorlab/trufflehog
 ```

You can then run the agent with the following command:
```shell
oxo scan run --agent agent/ostorlab/trufflehog file [YOUR_TARGET_FILE]
```


### Build directly from the repository

 1. To build the nuclei agent you need to have [oxo](https://pypi.org/project/ostorlab/) installed in your machine. If you have already installed oxo, you can skip this step.

```shell
pip3 install ostorlab
```

 2. Clone this repository.

```shell
git clone git@github.com:Ostorlab/agent_trufflehog.git && cd agent_trufflehog
```

 3. Build the agent image using oxo cli.

 ```shell
 oxo agent build --file=ostorlab.yaml
 ```

 You can pass the optional flag `--organization` or `-o` to specify your organisation. The organization is empty by default.

 4. Run the agent using on of the following commands:
	 * If you did not specify an organization when building the image:
    ```shell
    oxo scan run --agent agent//trufflehog file [YOUR_TARGET_FILE]
    ```
	 * If you specified an organization when building the image:
    ```shell
    oxo scan run --agent agent/[ORGANIZATION]/trufflehog file [YOUR_TARGET_FILE]
    ```


## License
[Apache](./LICENSE)
