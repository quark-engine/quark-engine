from quark.utils.colors import red, yel, cyan, bold, blue, lightyellow, lightblue


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
        ).format("19.10")
        +bold(lightblue(


            """
            An Obfuscation-Neglect Android Malware Scoring System
            """
        )
        )
    )
