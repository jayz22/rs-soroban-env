import matplotlib.pyplot as plt
import pandas as pd

df = pd.read_csv("./ct_div_rem_wrt_dividend_size.csv")
plt.plot(df['input'], df['cpu insns'])
# print(df)
