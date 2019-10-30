from utils.colors import red, yel, cyan, bold, blue


def logo():
    print(
        bold(
            yel(
                """
    ________                      __
    \_____  \  __ _______ _______|  | __
     /  / \  \|  |  \__  \\_  __ \  |/ /
    /   \_/.  \  |  // __ \|  | \/    <
    \_____\ \_/____/(____  /__|  |__|_ \\
           \__>          \/           \/ v{}
    """
            )
        ).format("0.0.0" + "-dev")
    )
