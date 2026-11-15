"""Where cgroup-signals' image is published: ONE setting.

`//cgroup-signals:image_push` and the publish workflow derive the coordinate
from the constants below; nothing else may spell the registry out.

    <IMAGE_REGISTRY>/<IMAGE_NAMESPACE>/cgroup-signals

Keep each assignment below on ONE line, exactly `NAME = "value"`, so a script
can read it with a line-anchored grep.
"""

# Registry host.
IMAGE_REGISTRY = "ghcr.io"

# Owner under the host.
IMAGE_NAMESPACE = "bpalermo"

def image_repository(component):
    """Repository path (no host) of a component's image.

    Args:
      component: "cgroup-signals".

    Returns:
      e.g. "bpalermo/cgroup-signals".
    """
    return "{}/{}".format(IMAGE_NAMESPACE, component)

def image_reference(component):
    """Host-qualified image repository of a component.

    Args:
      component: "cgroup-signals".

    Returns:
      e.g. "ghcr.io/bpalermo/cgroup-signals".
    """
    return "{}/{}".format(IMAGE_REGISTRY, image_repository(component))

# Where the chart is pushed, as an OCI artifact: `helm push` appends the
# chart's name, so the chart is oci://ghcr.io/bpalermo/charts/cgroup-signals.
CHART_REGISTRY_URL = "oci://{}/{}/charts".format(IMAGE_REGISTRY, IMAGE_NAMESPACE)
