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
        ).format("19.10")
        +bold(blue(


            """
            An Obfuscation-Neglect Android Malware Scoring System
            """
        )
        )
    )
