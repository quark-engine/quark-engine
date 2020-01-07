from quark.utils.colors import bold, lightyellow, lightblue


def logo():
    print(
        bold(
            lightyellow(
                """
    ________                      __
    \_____  \  __ _______ _______|  | __
     /  / \  \|  |  \__  \\_  __ \  |/ /
    /   \_/.  \  |  // __ \|  | \/    <
    \_____\ \_/____/(____  /__|  |__|_ \\
           \__>          \/           \/ v{}
    """
            )
        ).format("20.01")
        + bold(
            lightblue(
                """
            An Obfuscation-Neglect Android Malware Scoring System
            """
            )
        )
    )
