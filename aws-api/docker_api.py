import requests_unixsocket
import json
from typing import Dict, List, Optional, Any, Union
from urllib.parse import urlencode

DOCKER_SOCKET_PATH = 'http+unix://%2Fvar%2Frun%2Fdocker.sock'


class DockerAPIError(Exception):
    pass


class ContainerNotFoundError(DockerAPIError):
    pass


class ContainerCreationError(DockerAPIError):
    pass


class ContainerStartError(DockerAPIError):
    pass


class ContainerStopError(DockerAPIError):
    pass


class ContainerRemoveError(DockerAPIError):
    pass


class ContainerLogsError(DockerAPIError):
    pass


class ContainerExecError(DockerAPIError):
    pass


class DockerInfoError(DockerAPIError):
    pass


class ContainerListError(DockerAPIError):
    pass


class ContainerDetailError(DockerAPIError):
    pass


class ImagePullError(DockerAPIError):
    pass


class DockerClientWrapper:
    def __init__(self):
        self.session = requests_unixsocket.Session()
        self.containers = ContainerManager(self.session)
        self.images = ImageManager(self.session)

    def info(self) -> Dict[str, Any]:
        """Get system-wide information about Docker."""
        try:
            url = f'{DOCKER_SOCKET_PATH}/info'
            response = self.session.get(url)
            if response.status_code == 200:
                return response.json()
            else:
                raise DockerInfoError(f"Error: {response.status_code} - {response.text}")
        except Exception as e:
            raise DockerInfoError(str(e))

    def version(self) -> Dict[str, Any]:
        """Get version information about Docker."""
        try:
            url = f'{DOCKER_SOCKET_PATH}/version'
            response = self.session.get(url)
            if response.status_code == 200:
                return response.json()
            return {}
        except Exception:
            return {}

    def ping(self) -> bool:
        """Check if the Docker daemon is accessible."""
        try:
            url = f'{DOCKER_SOCKET_PATH}/_ping'
            response = self.session.get(url)
            return response.status_code == 200
        except Exception:
            return False


class ImageManager:
    def __init__(self, session):
        self.session = session

    def pull(self, repository: str, tag: str = 'latest') -> Dict[str, Any]:
        """Pull an image from a registry."""
        try:
            url = f'{DOCKER_SOCKET_PATH}/images/create?fromImage={repository}&tag={tag}'
            response = self.session.post(url)
            if response.status_code == 200:
                return {'status': 'success', 'repository': repository, 'tag': tag}
            else:
                raise ImagePullError(f"Error: {response.status_code} - {response.text}")
        except Exception as e:
            raise ImagePullError(str(e))

    def list(self, all: bool = False) -> List[Dict[str, Any]]:
        """List images."""
        try:
            url = f'{DOCKER_SOCKET_PATH}/images/json'
            if all:
                url += '?all=true'
            response = self.session.get(url)
            if response.status_code == 200:
                return response.json()
            return []
        except Exception:
            return []

    def get(self, image_id: str) -> Dict[str, Any]:
        """Get detailed information about an image."""
        try:
            url = f'{DOCKER_SOCKET_PATH}/images/{image_id}/json'
            response = self.session.get(url)
            if response.status_code == 200:
                return response.json()
            return {}
        except Exception:
            return {}

    def remove(self, image_id: str, force: bool = False) -> bool:
        """Remove an image."""
        try:
            url = f'{DOCKER_SOCKET_PATH}/images/{image_id}'
            if force:
                url += '?force=true'
            response = self.session.delete(url)
            return response.status_code in [200, 204]
        except Exception:
            return False


class ContainerManager:
    def __init__(self, session):
        self.session = session

    def create(self, image: str, command: Optional[Union[str, List[str]]] = None,
               name: Optional[str] = None, detach: bool = True,
               environment: Optional[Dict[str, str]] = None,
               ports: Optional[Dict[str, int]] = None,
               volumes: Optional[Dict[str, Dict[str, str]]] = None,
               labels: Optional[Dict[str, str]] = None,
               **kwargs) -> 'Container':
        """Create a container (mimics docker-py interface)."""

        # Build the container configuration
        config = {
            "Image": image,
            "AttachStdin": False,
            "AttachStdout": True,
            "AttachStderr": True,
            "Tty": False,
            "OpenStdin": False,
        }

        if command:
            if isinstance(command, str):
                config["Cmd"] = command.split()
            else:
                config["Cmd"] = command

        if environment:
            config["Env"] = [f"{k}={v}" for k, v in environment.items()]

        if labels:
            config["Labels"] = labels

        # Handle port bindings
        if ports:
            exposed_ports = {}
            port_bindings = {}
            for container_port, host_port in ports.items():
                # Format: '8080/tcp': 8080 or '8080': 8080
                if '/' not in str(container_port):
                    container_port = f"{container_port}/tcp"
                exposed_ports[container_port] = {}
                port_bindings[container_port] = [{"HostPort": str(host_port)}]

            config["ExposedPorts"] = exposed_ports
            if "HostConfig" not in config:
                config["HostConfig"] = {}
            config["HostConfig"]["PortBindings"] = port_bindings

        # Handle volumes
        if volumes:
            binds = []
            volume_dict = {}
            for host_path, container_config in volumes.items():
                bind_path = container_config.get('bind', '')
                mode = container_config.get('mode', 'rw')
                binds.append(f"{host_path}:{bind_path}:{mode}")
                volume_dict[bind_path] = {}

            if "HostConfig" not in config:
                config["HostConfig"] = {}
            config["HostConfig"]["Binds"] = binds
            config["Volumes"] = volume_dict

        # Add any additional host config options
        if kwargs:
            if "HostConfig" not in config:
                config["HostConfig"] = {}
            config["HostConfig"].update(kwargs.get("host_config", {}))

        # Create the container
        url = f'{DOCKER_SOCKET_PATH}/containers/create'
        if name:
            url += f'?name={name}'

        try:
            response = self.session.post(url, json=config)
            if response.status_code == 201:
                result = response.json()
                return Container(self.session, result['Id'])
            else:
                raise ContainerCreationError(f"Error: {response.status_code} - {response.text}")
        except Exception as e:
            raise ContainerCreationError(str(e))

    def run(self, image: str, command: Optional[Union[str, List[str]]] = None,
            detach: bool = True, remove: bool = False, **kwargs) -> Union['Container', bytes]:
        """Run a container (create and start)."""
        container = self.create(image, command=command, detach=detach, **kwargs)
        container.start()

        if not detach:
            logs = container.logs()
            if remove:
                container.remove(force=True)
            return logs

        if remove:
            # Note: Docker SDK typically handles auto-remove via HostConfig
            pass

        return container

    def get(self, container_id: str) -> 'Container':
        """Get a container by ID or name."""
        return Container(self.session, container_id)

    def list(self, all: bool = False, filters: Optional[Dict[str, Any]] = None,
             limit: int = -1) -> List['Container']:
        """List containers with filtering support."""
        try:
            url = f'{DOCKER_SOCKET_PATH}/containers/json'
            params = {}

            if all:
                params['all'] = 'true'

            if limit > 0:
                params['limit'] = str(limit)

            # Handle filters - ensure all filter values are lists
            if filters:
                # Normalize filters: ensure all values are lists
                normalized_filters = {}
                for key, value in filters.items():
                    if isinstance(value, list):
                        normalized_filters[key] = value
                    else:
                        normalized_filters[key] = [value]
                params['filters'] = json.dumps(normalized_filters)

            # Manually build query string since requests_unixsocket doesn't auto-encode
            if params:
                query_string = urlencode(params)
                url += f'?{query_string}'

            response = self.session.get(url)

            if response.status_code == 200:
                containers_data = response.json()
                return [Container(self.session, c['Id']) for c in containers_data]
            else:
                raise ContainerListError(f"Error: {response.status_code} - {response.text}")
        except Exception as e:
            raise ContainerListError(str(e))


    def prune(self, filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Remove stopped containers."""
        try:
            url = f'{DOCKER_SOCKET_PATH}/containers/prune'
            if filters:
                filter_json = json.dumps(filters)
                url += f'?filters={filter_json}'

            response = self.session.post(url)
            if response.status_code == 200:
                return response.json()
            return {}
        except Exception:
            return {}


class Container:
    """Represents a Docker container."""

    def __init__(self, session, container_id: str):
        self.session = session
        self.id = container_id
        self.short_id = container_id[:12]
        self._attrs = None

    def reload(self):
        """Refresh container attributes."""
        self._attrs = None
        return self.attrs

    @property
    def attrs(self) -> Dict[str, Any]:
        """Get container attributes."""
        if self._attrs is None:
            try:
                url = f'{DOCKER_SOCKET_PATH}/containers/{self.id}/json'
                response = self.session.get(url)
                if response.status_code == 200:
                    self._attrs = response.json()
                else:
                    raise ContainerDetailError(f"Error: {response.status_code} - {response.text}")
            except Exception as e:
                raise ContainerDetailError(str(e))
        return self._attrs

    @property
    def name(self) -> str:
        """Get container name."""
        name = self.attrs.get('Name', '')
        return name.lstrip('/') if name else ''

    @property
    def status(self) -> str:
        """Get container status."""
        return self.attrs.get('State', {}).get('Status', 'unknown')

    @property
    def image(self) -> str:
        """Get container image."""
        return self.attrs.get('Config', {}).get('Image', '')

    @property
    def labels(self) -> Dict[str, str]:
        """Get container labels."""
        return self.attrs.get('Config', {}).get('Labels', {})

    @property
    def ports(self) -> Dict[str, Any]:
        """Get container port mappings."""
        return self.attrs.get('NetworkSettings', {}).get('Ports', {})

    def start(self) -> None:
        """Start the container."""
        try:
            url = f'{DOCKER_SOCKET_PATH}/containers/{self.id}/start'
            response = self.session.post(url)
            if response.status_code not in [204, 304]:
                raise ContainerStartError(f"Error: {response.status_code} - {response.text}")
            self.reload()
        except Exception as e:
            raise ContainerStartError(str(e))

    def stop(self, timeout: int = 10) -> None:
        """Stop the container."""
        try:
            url = f'{DOCKER_SOCKET_PATH}/containers/{self.id}/stop?t={timeout}'
            response = self.session.post(url)
            if response.status_code not in [204, 304]:
                raise ContainerStopError(f"Error: {response.status_code} - {response.text}")
            self.reload()
        except Exception as e:
            raise ContainerStopError(str(e))

    def restart(self, timeout: int = 10) -> None:
        """Restart the container."""
        try:
            url = f'{DOCKER_SOCKET_PATH}/containers/{self.id}/restart?t={timeout}'
            response = self.session.post(url)
            if response.status_code != 204:
                raise ContainerStartError(f"Error: {response.status_code} - {response.text}")
            self.reload()
        except Exception as e:
            raise ContainerStartError(str(e))

    def kill(self, signal: str = 'SIGKILL') -> None:
        """Kill the container."""
        try:
            url = f'{DOCKER_SOCKET_PATH}/containers/{self.id}/kill?signal={signal}'
            response = self.session.post(url)
            if response.status_code != 204:
                raise ContainerStopError(f"Error: {response.status_code} - {response.text}")
            self.reload()
        except Exception as e:
            raise ContainerStopError(str(e))

    def remove(self, force: bool = False, v: bool = False) -> None:
        """Remove the container."""
        try:
            url = f'{DOCKER_SOCKET_PATH}/containers/{self.id}'
            params = []
            if force:
                params.append('force=true')
            if v:
                params.append('v=true')
            if params:
                url += '?' + '&'.join(params)

            response = self.session.delete(url)
            if response.status_code != 204:
                raise ContainerRemoveError(f"Error: {response.status_code} - {response.text}")
        except Exception as e:
            raise ContainerRemoveError(str(e))

    def logs(self, stdout: bool = True, stderr: bool = True,
             stream: bool = False, timestamps: bool = False,
             tail: Optional[int] = None, since: Optional[int] = None,
             follow: bool = False) -> Union[bytes, Any]:
        """Get container logs."""
        try:
            url = f'{DOCKER_SOCKET_PATH}/containers/{self.id}/logs'
            params = []

            if stdout:
                params.append('stdout=true')
            if stderr:
                params.append('stderr=true')
            if timestamps:
                params.append('timestamps=true')
            if tail is not None:
                params.append(f'tail={tail}')
            if since is not None:
                params.append(f'since={since}')
            if follow or stream:
                params.append('follow=true')

            if params:
                url += '?' + '&'.join(params)

            response = self.session.get(url, stream=stream)

            if stream or follow:
                return response.iter_content(chunk_size=1)

            if response.status_code == 200:
                return response.content
            else:
                raise ContainerLogsError(f"Error: {response.status_code} - {response.text}")
        except Exception as e:
            raise ContainerLogsError(str(e))

    def exec_run(self, cmd: Union[str, List[str]], stdout: bool = True,
                 stderr: bool = True, stdin: bool = False,
                 tty: bool = False, privileged: bool = False,
                 user: str = '', environment: Optional[Dict[str, str]] = None,
                 workdir: Optional[str] = None, detach: bool = False) -> tuple:
        """Execute a command in the container."""
        try:
            # Create exec instance
            exec_config = {
                "AttachStdin": stdin,
                "AttachStdout": stdout,
                "AttachStderr": stderr,
                "Tty": tty,
                "Cmd": cmd if isinstance(cmd, list) else cmd.split(),
                "Privileged": privileged,
            }

            if user:
                exec_config["User"] = user
            if environment:
                exec_config["Env"] = [f"{k}={v}" for k, v in environment.items()]
            if workdir:
                exec_config["WorkingDir"] = workdir

            url = f'{DOCKER_SOCKET_PATH}/containers/{self.id}/exec'
            response = self.session.post(url, json=exec_config)

            if response.status_code != 201:
                raise ContainerExecError(f"Error creating exec: {response.status_code}")

            exec_id = response.json()['Id']

            # Start exec
            start_config = {
                "Detach": detach,
                "Tty": tty,
            }

            url = f'{DOCKER_SOCKET_PATH}/exec/{exec_id}/start'
            response = self.session.post(url, json=start_config)

            if detach:
                return (0, b'')

            output = response.content if response.status_code == 200 else b''

            # Get exit code
            url = f'{DOCKER_SOCKET_PATH}/exec/{exec_id}/json'
            response = self.session.get(url)
            exit_code = 0
            if response.status_code == 200:
                exit_code = response.json().get('ExitCode', 0)

            return (exit_code, output)
        except Exception as e:
            raise ContainerExecError(str(e))

    def stats(self, stream: bool = False) -> Union[Dict[str, Any], Any]:
        """Get container stats."""
        try:
            url = f'{DOCKER_SOCKET_PATH}/containers/{self.id}/stats'
            if not stream:
                url += '?stream=false'

            response = self.session.get(url, stream=stream)

            if stream:
                return response.iter_lines()

            if response.status_code == 200:
                return response.json()
            return {}
        except Exception:
            return {}

    def wait(self, timeout: Optional[int] = None) -> Dict[str, Any]:
        """Wait for the container to stop."""
        try:
            url = f'{DOCKER_SOCKET_PATH}/containers/{self.id}/wait'
            response = self.session.post(url, timeout=timeout)
            if response.status_code == 200:
                return response.json()
            return {}
        except Exception:
            return {}

    def __repr__(self):
        return f"<Container: {self.short_id}>"



if __name__ == '__main__':

    # Example usage
    client = DockerClientWrapper()


    status = 'running'
    function_name = 'localcloud-api-1'
    filters = {
        'label': [
            'localcloud=true',
            f'function-name={function_name}'
        ]
    }

    filters['status'] = status

    print(client.containers.list(all=(status is None), filters=filters))

    # # Test connectivity
    # print(f"Docker accessible: {client.ping()}")

    # # List all containers
    # print("\n=== All Containers ===")
    # containers = client.containers.list(all=True)
    # for container in containers:
    #     print(f"ID: {container.short_id}, Name: {container.name}, Status: {container.status}")

    # # List only running containers
    # print("\n=== Running Containers ===")
    # running = client.containers.list(all=False)
    # for container in running:
    #     print(f"ID: {container.short_id}, Name: {container.name}")

    # # Filter by name
    # print("\n=== Filter by Name (portainer) ===")
    # filtered = client.containers.list(all=True, filters={"name": ["portainer"]})
    # for container in filtered:
    #     print(f"ID: {container.short_id}, Name: {container.name}, Image: {container.image}")

    # # Filter by status
    # print("\n=== Filter by Status (running) ===")
    # filtered = client.containers.list(filters={"status": ["running"]})
    # for container in filtered:
    #     print(f"ID: {container.short_id}, Name: {container.name}")

    # # Filter by label
    # print("\n=== Filter by Label ===")
    # filtered = client.containers.list(all=True, filters={"label": ["io.portainer.server=true"]})
    # for container in filtered:
    #     print(f"ID: {container.short_id}, Name: {container.name}, Labels: {container.labels}")

    # # Filter by multiple labels (like your example)
    # print("\n=== Filter by Multiple Labels ===")
    # filtered = client.containers.list(all=True, filters={
    #     "label": [
    #         "io.portainer.server=true",
    #         "org.opencontainers.image.title=Portainer"
    #     ]
    # })
    # for container in filtered:
    #     print(f"ID: {container.short_id}, Name: {container.name}")
    #     print(f"  Labels: {container.labels}")